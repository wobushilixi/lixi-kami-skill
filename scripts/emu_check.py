#!/usr/bin/env python3
"""emu_check.py - 离线仿真卡密校验函数（Unicorn），无设备/无 Frida 时的动态兜底。

用途（A 类本地算法 + 部分 B 类解析后判定）:
    1) 判定点定位自证：跑原函数，无效输入 → 假；证明"找对了判定点"
    2) 补丁差分验证：同一输入，--patch 前后返回值不同 → 补丁语义被证实（无真机也能闭环）
    3) 接受集搜索：小空间/前缀爆破，找能被接受的输入
    4) 算法观察：--trace 看指令流；--dump 看函数写出的缓冲区（解密串、生成码）

用法:
    # 列函数/导入（先找目标函数）
    python emu_check.py --elf libfoo.so --list

    # 跑校验函数：x0 = 卡密字符串指针
    python emu_check.py --elf libfoo.so --sym check_key --arg "TEST-KEY-123"

    # 参数模式：cstr(x0=ptr) / ptr_len(x0=ptr,x1=len) / int / ints(多个立即数进 x0,x1..)
    python emu_check.py --elf libfoo.so --sym verify --arg "ABC" --arg-mode ptr_len

    # 差分验证：同一 key，打补丁前后返回值不同 = 补丁逻辑被证实
    python emu_check.py --elf libfoo.so --sym check_key --arg "BAD" --expect 0
    python emu_check.py --elf libfoo.so --sym check_key --arg "BAD" --expect 1 --patch 0x2A1C4:20008052

    # 原始代码块（无 ELF 头，如内存 dump 出来的函数）
    python emu_check.py --raw dump.bin --base 0x100000 --func 0x100000 --arg X

地址口径（重要）:
    --sym / --func / --patch 里的地址 = IDA / Ghidra 里直接看到的值（文件内 vaddr）。
    ET_DYN(PIE/so) 会自动加 --base（默认 0x10000000）；--raw 需自己给 --base。

已模拟的 libc（PLT 自动拦截）:
    strlen strcmp strncmp strcasecmp memcmp memcpy memmove memset strcpy strncpy
    strchr strrchr strstr atoi strtol tolower toupper
    malloc calloc free realloc time gettimeofday rand srand
    __stack_chk_fail(直接判失败) __android_log_print pthread_mutex_*/cond_* __cxa_atexit
已模拟的 syscall:
    write exit/exit_group getrandom clock_gettime gettimeofday mmap mprotect munmap
    set_tid_address futex getpid gettid
    其余未知 syscall 返回 -ENOSYS 并打印告警（可能影响结果，输出里会汇总）

局限（如实对待，别当万能的用）:
    - 依赖 TLS 的函数：已提供零页 TLS（TPIDR_EL0），stack canary 可过；但复杂的
      pthread/TLS 逻辑可能仍异常
    - 未知导入函数返回 0，会让结果失真 —— 结尾会打印"未模拟导入"清单，命中即降置信度
    - 需要真实文件/网络的函数不适合仿真，走真机或 mock

退出码: 0=正常结束  2=用法错误  3=--expect 不符  4=仿真故障(崩溃/超限)
"""

import argparse
import struct
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM,
                     UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_UNMAPPED,
                     UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X8, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC,
    UC_ARM64_REG_TPIDR_EL0)

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
except Exception:
    MD = None

# ---------------- 内存布局 ----------------
BASE_DEFAULT = 0x10000000        # ET_DYN 装载基址
SCRATCH = 0x60000000             # 参数字符串
SCRATCH_SZ = 4 * 1024 * 1024
HEAP = 0x50000000                # malloc/brk 用
HEAP_SZ = 64 * 1024 * 1024
STACK = 0x7F000000
STACK_SZ = 4 * 1024 * 1024
TLS_ADDR = 0x7E000000
TLS_SZ = 16 * 1024
MAGIC_LR = 0x0BADF00D0000        # 假返回地址，命中即停
JNI_STUB_BASE = 0x68000000       # 假 JNIEnv 函数桩（每条 8 字节，内容 ret，由 code hook 拦截）
JNI_STUB_SZ = 256 * 1024
ENV_TABLE = 0x6A000000           # 假 JNIEnv 函数表
ENV_TABLE_SZ = 4096
ENV_PTR = 0x6A001000             # 存放"表地址"的槽位：JNIEnv* → 指向它

PAGE = 0x1000


def align_down(a):
    return a & ~(PAGE - 1)


def align_up(a):
    return (a + PAGE - 1) & ~(PAGE - 1)


# ---------------- libc 模拟 ----------------
class LibcEmu:
    """PLT 拦截：以 python 实现常用 libc，让校验函数能跑完。"""

    def __init__(self, uc, log):
        self.uc = uc
        self.log = log
        self.unknown_used = set()
        self.stackfail = False
        self._rand = 0x12345678
        self._heap = HEAP + 0x10000
        self.table = {
            "strlen": self._strlen, "strcmp": self._strcmp, "strncmp": self._strncmp,
            "strcasecmp": self._strcasecmp, "memcmp": self._memcmp,
            "memcpy": self._memcpy, "memmove": self._memcpy, "memset": self._memset,
            "strcpy": self._strcpy, "strncpy": self._strncpy,
            "strchr": self._strchr, "strrchr": self._strrchr, "strstr": self._strstr,
            "atoi": self._atoi, "strtol": self._strtol,
            "tolower": self._tolower, "toupper": self._toupper,
            "malloc": self._malloc, "calloc": self._calloc, "free": self._free,
            "_Znwm": self._malloc, "_Znam": self._malloc, "_ZdlPv": self._free,
            "_ZdaPv": self._free, "_Znwj": self._malloc, "_Zdaj": self._free,
            "__cxa_guard_acquire": lambda: 1, "__cxa_guard_release": self._ret0,
            "__cxa_guard_abort": self._ret0, "__errno": self._errno_fn,
            "__cxa_allocate_exception": lambda: self._malloc(),
            "__cxa_free_exception": self._free, "__cxa_throw": self._throw,
            "__cxa_begin_catch": lambda: 0, "__cxa_end_catch": self._ret0,
            "__cxa_rethrow": self._ret0, "__cxa_pure_virtual": self._throw,
            "pthread_rwlock_rdlock": self._ret0, "pthread_rwlock_wrlock": self._ret0,
            "pthread_rwlock_unlock": self._ret0, "pthread_mutex_lock": self._ret0,
            "pthread_mutex_unlock": self._ret0, "pthread_once": self._ret0,
            "dl_iterate_phdr": lambda: 0, "abort": self._abort,
            "_ZSt9terminatev": self._abort, "__memcpy_chk": self._memcpy_chk,
            "__strlen_chk": lambda: self._strlen(), "__vsnprintf_chk": self._vsnprintf,
            "fopen": lambda: 0, "fclose": lambda: 0, "fread": lambda: 0,
            "fwrite": lambda: 0, "fseek": lambda: 0, "fseeko": lambda: 0,
            "ftello": lambda: 0, "fflush": lambda: 0, "remove": lambda: 0,
            "localeconv": lambda: 0, "syscall": self._syscall_emu,
            "realloc": self._realloc, "time": self._time, "gettimeofday": self._gettimeofday,
            "rand": self._rand_fn, "srand": self._srand,
            "__stack_chk_fail": self._stackchk, "__stack_chk_fail_local": self._stackchk,
            "__android_log_print": self._logprint,
            "__cxa_atexit": self._ret0, "__cxa_finalize": self._ret0,
            "getpid": lambda: 1234, "gettid": lambda: 1234,
            # 网络系：显式模拟为"失败"，让 B/C 类代码的网络分支可预测地走失败路径
            "socket": self._netfail, "connect": self._netfail, "sendto": self._netfail,
            "recvfrom": self._netfail, "send": self._netfail, "recv": self._netfail,
            "close": self._ret0, "getaddrinfo": self._netfail, "gethostbyname": self._netfail,
        }

    def _netfail(self):
        self.log("[libc] 网络调用被模拟为失败（-1）；要观察联网分支请改 mock 或真机")
        return -1 & 0xFFFFFFFFFFFFFFFF

    # --- 读取辅助 ---
    def _rd(self, addr, n):
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            return b""

    def _cstr(self, addr, cap=4096):
        out = bytearray()
        while len(out) < cap:
            b = self._rd(addr + len(out), 1)
            if not b or b == b"\x00":
                break
            out += b
        return bytes(out)

    # --- 各函数 ---
    def _strlen(self):
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))
        return len(s)

    def _strcmp(self):
        a = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))
        b = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1))
        return 0 if a == b else (1 if a > b else -1)

    def _strncmp(self):
        n = self.uc.reg_read(UC_ARM64_REG_X2)
        a = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))[:n]
        b = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1))[:n]
        return 0 if a == b else (1 if a > b else -1)

    def _strcasecmp(self):
        a = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0)).lower()
        b = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1)).lower()
        return 0 if a == b else (1 if a > b else -1)

    def _memcmp(self):
        n = self.uc.reg_read(UC_ARM64_REG_X2)
        a = self._rd(self.uc.reg_read(UC_ARM64_REG_X0), n)
        b = self._rd(self.uc.reg_read(UC_ARM64_REG_X1), n)
        return 0 if a == b else (1 if a > b else -1)

    def _memcpy(self):
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        src = self.uc.reg_read(UC_ARM64_REG_X1)
        n = self.uc.reg_read(UC_ARM64_REG_X2)
        self.uc.mem_write(dst, self._rd(src, n))
        return dst

    def _memset(self):
        ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        val = self.uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        n = self.uc.reg_read(UC_ARM64_REG_X2)
        self.uc.mem_write(ptr, bytes([val]) * n)
        return ptr

    def _strcpy(self):
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1))
        self.uc.mem_write(dst, s + b"\x00")
        return dst

    def _strncpy(self):
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        n = self.uc.reg_read(UC_ARM64_REG_X2)
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1), cap=n)
        self.uc.mem_write(dst, s + b"\x00" * (n - len(s)))
        return dst

    def _strchr(self):
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))
        c = self.uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        idx = s.find(bytes([c]))
        return self.uc.reg_read(UC_ARM64_REG_X0) + idx if idx >= 0 else 0

    def _strrchr(self):
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))
        c = self.uc.reg_read(UC_ARM64_REG_X1) & 0xFF
        idx = s.rfind(bytes([c]))
        return self.uc.reg_read(UC_ARM64_REG_X0) + idx if idx >= 0 else 0

    def _strstr(self):
        h = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0))
        n = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1))
        idx = h.find(n)
        return self.uc.reg_read(UC_ARM64_REG_X0) + idx if idx >= 0 else 0

    def _atoi(self):
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0)).strip()
        try:
            num = int(s.split(b"\x00")[0] or b"0")
        except Exception:
            num = 0
        return num & 0xFFFFFFFF

    def _strtol(self):
        s = self._cstr(self.uc.reg_read(UC_ARM64_REG_X0)).strip()
        try:
            num = int(s, self.uc.reg_read(UC_ARM64_REG_X2) or 10)
        except Exception:
            num = 0
        return num & 0xFFFFFFFFFFFFFFFF

    def _tolower(self):
        return ord(chr(self.uc.reg_read(UC_ARM64_REG_X0) & 0xFF).lower())
    
    def _toupper(self):
        return ord(chr(self.uc.reg_read(UC_ARM64_REG_X0) & 0xFF).upper())

    def _malloc(self):
        n = self.uc.reg_read(UC_ARM64_REG_X0)
        p = self._heap
        self._heap = (self._heap + n + 16 + 15) & ~15
        if self._heap > HEAP + HEAP_SZ:
            self.log("[libc] malloc 堆耗尽")
            return 0
        self.uc.mem_write(p, b"\x00" * min(n, 4096))
        return p

    def _calloc(self):
        n = self.uc.reg_read(UC_ARM64_REG_X0) * self.uc.reg_read(UC_ARM64_REG_X1)
        p = self._malloc()
        if p:
            self.uc.mem_write(p, b"\x00" * n)
        return p

    def _free(self):
        return 0

    def _realloc(self):
        return self._malloc()

    def _time(self):
        return 1700000000

    def _gettimeofday(self):
        tv = self.uc.reg_read(UC_ARM64_REG_X0)
        if tv:
            self.uc.mem_write(tv, struct.pack("<qq", 1700000000, 0))
        return 0

    def _rand_fn(self):
        self._rand = (self._rand * 1103515245 + 12345) & 0x7FFFFFFF
        return self._rand

    def _srand(self):
        self._rand = self.uc.reg_read(UC_ARM64_REG_X0) or 1
        return 0

    def _stackchk(self):
        self.stackfail = True
        raise SystemExit("stack_chk_fail")  # 由外层捕获 → 判定为"栈保护失败"

    def _abort(self):
        raise SystemExit("abort")   # abort/terminate = 代码走了致命失败分支，停下并报告

    def _throw(self):
        raise SystemExit("cpp_throw")   # C++ 异常：多数是错误分支，停下并报告（有诊断价值）

    def _errno_fn(self):
        return HEAP + 0x8000

    def _memcpy_chk(self):
        return self._memcpy()

    def _vsnprintf(self):
        # __vsnprintf_chk(dst, maxlen, flags, buflen, fmt, va) → 只写空串并记录格式串
        fmt = self._cstr(self.uc.reg_read(UC_ARM64_REG_X4)).decode("utf-8", "replace")
        self.log("[libc] __vsnprintf_chk(fmt=%r) → 输出空串（精度损失）" % fmt)
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        if dst:
            self.uc.mem_write(dst, b"\x00")
        return 0

    def _syscall_emu(self):
        nr = self.uc.reg_read(UC_ARM64_REG_X0)
        self.log("[libc] syscall(%d) → -ENOSYS（本仿真只处理内联 svc）" % nr)
        return -38 & 0xFFFFFFFFFFFFFFFF

    def _logprint(self):
        prio = self.uc.reg_read(UC_ARM64_REG_X0)
        tag = self._cstr(self.uc.reg_read(UC_ARM64_REG_X1)).decode("utf-8", "replace")
        fmt = self._cstr(self.uc.reg_read(UC_ARM64_REG_X2)).decode("utf-8", "replace")
        self.log("[libc] __android_log_print(%d, %s, %s)" % (prio, tag, fmt))
        return 0

    def _ret0(self):
        return 0

    # --- 调度 ---
    def call(self, name):
        fn = self.table.get(name)
        if fn is None:
            if name not in self.unknown_used:
                self.unknown_used.add(name)
                self.log("[libc] 未模拟导入 %s → 返回 0（结果可能失真；如有依赖库请 --dep 加载）" % name)
            return 0
        try:
            return fn()
        except SystemExit:
            raise
        except Exception as e:
            self.log("[libc] %s 模拟出错：%s" % (name, e))
            return 0


# ---------------- 假 JNIEnv ----------------
class JniEmu:
    """给 native 卡密函数（Java_xxx_nativeVerify）配一个可运行的假 JNIEnv。

    jstring / jbyteArray 用「指向 UTF-8 字节的指针」表示；函数表指向一页桩，
    桩由 code hook 拦截后在本类里模拟，返回后把 PC 设回 LR（等价 ret）。
    未模拟的 JNI 函数返回 0 并记录（结尾打印，命中即降置信度）。
    """

    def __init__(self, uc, log):
        self.uc = uc
        self.log = log
        self.unknown = set()
        self.stubs = {}
        for i in range(JNI_STUB_SZ // 8):
            self.stubs[JNI_STUB_BASE + i * 8] = i
        table = b"".join(struct.pack("<Q", JNI_STUB_BASE + i * 8)
                         for i in range(ENV_TABLE_SZ // 8))
        uc.mem_write(ENV_TABLE, table)
        uc.mem_write(ENV_PTR, struct.pack("<Q", ENV_TABLE))
        self._jni_scratch = 0x6B000000
        self.table = {
            6: self._findclass, 14: self._thrownew, 15: lambda: 0, 17: lambda: 0,
            28: lambda: 0, 30: lambda: 0, 31: self._getobjclass, 33: self._getid,
            34: lambda: 0, 36: lambda: 0, 37: lambda: 0, 38: lambda: 0, 49: lambda: 0,
            61: lambda: 0, 94: self._getid, 100: self._getid, 113: self._getid,
            144: self._getid, 145: lambda: 0, 150: lambda: 0, 155: lambda: 0,
            165: self._strlen, 167: self._newstring, 168: self._strlen, 169: self._getutf,
            170: lambda: 0, 171: lambda: 0, 172: lambda: 0, 176: self._newbytes,
            184: self._getbytes, 193: lambda: 0, 200: self._getregion,
            208: self._setregion, 215: self._registernatives, 219: self._getjavavm,
            228: lambda: 0, 229: self._thrownew,
        }
        for i in (35, 39, 40, 41, 44, 45, 46, 50, 51, 52, 53, 62, 63, 64):
            self.table.setdefault(i, lambda: 0)

    # --- handlers ---
    def _x(self, i):
        return self.uc.reg_read([UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5][i])

    def _cstr(self, addr, cap=4096):
        out = bytearray()
        while len(out) < cap:
            try:
                b = bytes(self.uc.mem_read(addr + len(out), 1))
            except Exception:
                break
            if b == b"\x00":
                break
            out += b
        return bytes(out)

    def _findclass(self):
        self.log("[jni] FindClass(%r)" % self._cstr(self._x(1)).decode("utf-8", "replace"))
        return self._x(1)

    def _getobjclass(self):
        return self._x(1)

    def _getid(self):
        self.log("[jni] Get*ID(%r)" % self._cstr(self._x(2)).decode("utf-8", "replace"))
        return self._x(2)

    def _strlen(self):
        return len(self._cstr(self._x(1)))

    def _newstring(self):
        return self._x(1)   # jstring = 指向 UTF-8 的指针

    def _getutf(self):
        if self._x(2):
            self.uc.mem_write(self._x(2), b"\x00")   # isCopy = false
        return self._x(1)

    def _newbytes(self):
        n = self._x(1)
        p = self._jni_scratch
        self._jni_scratch = (self._jni_scratch + n + 16) & ~15
        self.uc.mem_write(p, b"\x00" * min(n, 4096))
        return p

    def _getbytes(self):
        if self._x(2):
            self.uc.mem_write(self._x(2), b"\x00")
        return self._x(1)

    def _setregion(self):
        src, dst, n = self._x(3), self._x(1), self._x(4)
        if src and dst and n:
            self.uc.mem_write(dst, bytes(self.uc.mem_read(src, n)))
        return 0

    def _getregion(self):
        src, dst, n = self._x(1), self._x(3), self._x(4)
        if src and dst and n:
            self.uc.mem_write(dst, bytes(self.uc.mem_read(src, n)))
        return 0

    def _registernatives(self):
        self.log("[jni] RegisterNatives 被调用（动态注册）")
        return 0

    def _getjavavm(self):
        if self._x(1):
            self.uc.mem_write(self._x(1), struct.pack("<Q", ENV_PTR))
        return 0

    def _thrownew(self):
        cls = self._cstr(self._x(1)).decode("utf-8", "replace")
        msg = self._cstr(self._x(2)).decode("utf-8", "replace")
        self.log("[jni] ThrowNew(%s, %s) ← 说明代码认为走到了失败分支" % (cls, msg))
        return 0

    def call(self, idx):
        fn = self.table.get(idx)
        if fn is None:
            self.unknown.add(idx)
            self.log("[jni] 未模拟 JNIEnv 函数 #%d → 返回 0" % idx)
            return 0
        try:
            return fn() or 0
        except Exception as e:
            self.log("[jni] #%d 模拟出错：%s" % (idx, e))
            return 0


# ---------------- ELF 解析 ----------------
class ElfImage:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("不是 ELF 文件")
        if d[4] != 2 or d[5] != 1:
            raise ValueError("仅支持 ELF64 little-endian")
        (self.e_type, self.e_machine, _ver, self.e_entry, self.e_phoff, self.e_shoff,
         _flags, _ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        self.segments = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from("<IIQQQQQQ", d, off)
            self.segments.append(dict(type=p_type, flags=p_flags, off=p_offset,
                                      vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))
        self.sections = {}
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _link, _info, \
                _align, sh_entsize = struct.unpack_from("<IIQQQQIIQQ", d, off)
            self.sections[i] = dict(nameoff=sh_name, type=sh_type, addr=sh_addr,
                                    off=sh_offset, size=sh_size, entsize=sh_entsize)
        shstr = b""
        if self.e_shstrndx < self.e_shnum:
            s = self.sections[self.e_shstrndx]
            shstr = d[s["off"]:s["off"] + s["size"]]
        for i, s in self.sections.items():
            n_end = shstr.find(b"\x00", s["nameoff"])
            s["name"] = shstr[s["nameoff"]:n_end].decode("utf-8", "replace") if shstr else ""

    def sec(self, name):
        for s in self.sections.values():
            if s.get("name") == name:
                return s
        return None

    def dynsyms(self):
        """返回 [(name, value, shndx)]；依赖 .dynsym/.dynstr + 动态段。"""
        out = []
        dynsym = self.sec(".dynsym")
        dynstr = self.sec(".dynstr")
        if not dynsym or not dynstr:
            return out
        strtab = self.data[dynstr["off"]:dynstr["off"] + dynstr["size"]]
        n = dynsym["size"] // 24
        for i in range(n):
            off = dynsym["off"] + i * 24
            st_name, st_info, _other, st_shndx, st_value, _size = \
                struct.unpack_from("<IBBHQQ", self.data, off)
            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode("utf-8", "replace") if st_name else ""
            out.append((name, st_value, st_shndx))
        return out

    def symtab(self):
        out = []
        sym = self.sec(".symtab")
        strsec = self.sec(".strtab")
        if not sym or not strsec:
            return out
        strtab = self.data[strsec["off"]:strsec["off"] + strsec["size"]]
        n = sym["size"] // 24
        for i in range(n):
            off = sym["off"] + i * 24
            st_name, st_info, _other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", self.data, off)
            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode("utf-8", "replace") if st_name else ""
            out.append((name, st_value, st_shndx, st_size))
        return out

    def relocs(self):
        """返回 (rela_dyn 列表, plt 列表)，每项 (r_offset, type, symname, addend)。"""
        dynsym = self.dynsyms()
        def rela_table(sec):
            if not sec:
                return []
            res = []
            n = sec["size"] // 24
            for i in range(n):
                off = sec["off"] + i * 24
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
                rtype = r_info & 0xFFFFFFFF
                rsym = r_info >> 32
                name = dynsym[rsym][0] if rsym < len(dynsym) else ""
                res.append((r_offset, rtype, name, r_addend))
            return res
        return rela_table(self.sec(".rela.dyn")), rela_table(self.sec(".rela.plt"))

    def plt_entries(self, base=0):
        """返回 ({运行时桩地址: 符号名}, entsize)（aarch64: .plt + 16 + idx*16）。"""
        plt = self.sec(".plt")
        rplt = self.sec(".rela.plt")
        if not plt or not rplt:
            return {}, 0
        _, list_ = self.relocs()
        entsize = plt["entsize"] or 16
        ents = {}
        # .plt[0]=resolver, .plt[1..] = 各 stub
        stub0 = base + plt["addr"] + 2 * entsize
        for i, (_o, _t, name, _a) in enumerate(list_):
            ents[stub0 + i * entsize] = name
        return ents, entsize


def load_elf(uc, img, base):
    # PT_LOAD 段之间常有页级重叠（R 段与 RX 段共享首尾页），
    # 先归并所有页区间再逐段映射，避免重叠 mem_map 失败后写入落到未映射区。
    pages = set()
    for seg in img.segments:
        if seg["type"] != 1 or seg["memsz"] == 0:
            continue
        s = align_down(base + seg["vaddr"])
        e = align_up(base + seg["vaddr"] + seg["memsz"])
        for p in range(s, e, PAGE):
            pages.add(p)
    if not pages:
        return base
    ps = sorted(pages)
    run_start = prev = ps[0]
    for p in ps[1:] + [None]:
        if p is not None and p == prev + PAGE:
            prev = p
            continue
        uc.mem_map(run_start, prev + PAGE - run_start, UC_PROT_ALL)
        if p is None:
            break
        run_start = prev = p
    for seg in img.segments:
        if seg["type"] != 1 or seg["filesz"] == 0:
            continue
        try:
            uc.mem_write(base + seg["vaddr"], img.data[seg["off"]:seg["off"] + seg["filesz"]])
        except UcError as e:
            print("[emu] 段写入失败 vaddr=0x%x filesz=%d: %s" % (seg["vaddr"], seg["filesz"], e))
    return base


def apply_relocs(uc, img, base, plt_ents, unknown_stub, extra_syms=None, emulated=frozenset()):
    rela_dyn, rela_plt = img.relocs()
    R_RELATIVE, R_JUMP_SLOT, R_GLOB_DAT, R_ABS64 = 1027, 1026, 1025, 257
    plt_by_name = {}
    for a, n in plt_ents.items():
        plt_by_name.setdefault(n, a)
    for r_offset, rtype, name, addend in rela_dyn + rela_plt:
        addr = base + r_offset
        try:
            if rtype == R_RELATIVE:
                uc.mem_write(addr, struct.pack("<Q", base + addend))
            elif rtype in (R_JUMP_SLOT, R_GLOB_DAT):
                # 解析优先级：本 lib 模拟器桩（被 code hook 拦截）> 依赖库真实导出 > 本 lib 其他桩 > 未知桩
                target = None
                if name in emulated and name in plt_by_name:
                    target = plt_by_name[name]
                elif extra_syms and name in extra_syms:
                    target = extra_syms[name]
                elif name in plt_by_name:
                    target = plt_by_name[name]
                else:
                    target = unknown_stub
                uc.mem_write(addr, struct.pack("<Q", target))
            elif rtype == R_ABS64:
                uc.mem_write(addr, struct.pack("<Q", base + addend))
        except UcError:
            pass


# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser(add_help=True, description="离线仿真 arm64 校验函数（Unicorn）")
    ap.add_argument("--elf")
    ap.add_argument("--raw")
    ap.add_argument("--dep", action="append", default=[],
                    help="依赖库（可多次），如 --dep libc++_shared.so：装载后其导出符号由真实代码执行")
    ap.add_argument("--base", default=None, help="装载基址（默认 ET_DYN=0x10000000，raw=0x10000000）")
    ap.add_argument("--func", help="函数地址（文件内 vaddr，十六进制）")
    ap.add_argument("--sym", help="函数名（优先 .symtab，再 .dynsym）")
    ap.add_argument("--arg", action="append", default=[], help="参数（可多次）")
    ap.add_argument("--arg-mode", default="cstr",
                    choices=["cstr", "ptr_len", "int", "ints", "jni_str", "jni_mix"],
                    help="cstr: x0=字符串指针; ptr_len: x0=ptr x1=len; int: x0=整数; "
                         "ints: 多个整数进 x0..; jni_str/jni_mix: x0=假JNIEnv, x2..=jstring"
                         "(jni_mix 用 s:/i:/n: 前缀区分字符串/整数/null)")
    ap.add_argument("--patch", action="append", default=[], help="ADDR:HEX 运行时改字节（可多次）")
    ap.add_argument("--list", action="store_true", help="列出导入/导出函数")
    ap.add_argument("--trace", action="store_true", help="打印指令流（截断）")
    ap.add_argument("--max-insn", type=int, default=20000000)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--expect", type=int, default=None, help="断言 w0，违者退出码 3")
    ap.add_argument("--dump", action="append", default=[],
                    help="结束后 dump 内存 REG:LEN，如 x1:64（可多次）")
    args = ap.parse_args()

    if not args.elf and not args.raw:
        print(__doc__)
        return 2

    img = None
    if args.elf:
        img = ElfImage(args.elf)
        base = int(args.base, 16) if args.base else (BASE_DEFAULT if img.e_type == 3 else 0)
    else:
        base = int(args.base, 16) if args.base else BASE_DEFAULT

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    loglines = []

    def log(msg):
        loglines.append(msg)
        print(msg)

    # --- 独立区块 ---
    libc = LibcEmu(uc, log)
    dep_exports = {}
    if img:
        load_elf(uc, img, base)
        plt_ents, _ = img.plt_entries(base)
        unknown_stub = SCRATCH + SCRATCH_SZ - 0x100
    else:
        plt_ents = {}
        unknown_stub = 0

    uc.mem_map(SCRATCH, SCRATCH_SZ, UC_PROT_ALL)
    uc.mem_map(HEAP, HEAP_SZ, UC_PROT_ALL)
    uc.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
    uc.mem_map(TLS_ADDR, TLS_SZ, UC_PROT_ALL)
    uc.mem_map(0x6B000000, 1 * 1024 * 1024, UC_PROT_ALL)     # JNI 假数组/字符串区
    try:
        uc.mem_map(JNI_STUB_BASE, JNI_STUB_SZ, UC_PROT_ALL)
        uc.mem_map(ENV_TABLE, ENV_TABLE_SZ + PAGE, UC_PROT_ALL)   # +1 页给 ENV_PTR 槽位
    except UcError:
        pass
    uc.mem_write(JNI_STUB_BASE, struct.pack("<I", 0xD65F03C0) * (JNI_STUB_SZ // 4))  # 桩：ret
    uc.mem_map(align_down(MAGIC_LR), PAGE * 2, UC_PROT_ALL)
    uc.mem_write(align_down(MAGIC_LR), struct.pack("<I", 0xD503201F) * (PAGE // 2))  # NOP 填充
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR + 0x100)
    sp = STACK + STACK_SZ // 2
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_LR, MAGIC_LR)
    uc.mem_write(sp, struct.pack("<Q", 0))

    if img:
        apply_relocs(uc, img, base, plt_ents, unknown_stub)
        # --- 依赖库：真实代码执行（libc++_shared 等），解决 std::string/ostream 类未模拟问题 ---
        for i, dpath in enumerate(args.dep):
            try:
                dimg = ElfImage(dpath)
            except Exception as e:
                log("[-] --dep 加载失败 %s：%s" % (dpath, e))
                continue
            dbase = 0x20000000 + i * 0x2000000
            load_elf(uc, dimg, dbase)
            dplt, _ = dimg.plt_entries(dbase)
            plt_ents.update(dplt)
            apply_relocs(uc, dimg, dbase, dplt, unknown_stub, extra_syms=dep_exports)
            n_exp = 0
            for n, v, x in dimg.dynsyms():
                if n and x != 0:
                    dep_exports.setdefault(n, dbase + v)
                    n_exp += 1
            log("[emu] 依赖已加载：%s @0x%x（真实导出 %d 个符号）" % (dpath, dbase, n_exp))
        if dep_exports:
            # 重新解析主模块 GOT：能落到依赖库真实实现的符号改指过去（模拟器桩优先）
            apply_relocs(uc, img, base, plt_ents, unknown_stub,
                         extra_syms=dep_exports, emulated=set(libc.table.keys()))

    if args.raw:
        with open(args.raw, "rb") as f:
            blob = f.read()
        try:
            uc.mem_map(base, align_up(len(blob)) + PAGE, UC_PROT_ALL)
        except UcError:
            pass
        uc.mem_write(base, blob)

    # --- --list：先列符号（不要求 --sym/--func）---
    if args.list and img:
        print("[emu] === 导出/本地函数（.symtab）===")
        for n, v, x, sz in img.symtab():
            if n and x != 0:
                print("  0x%08x  size=%-6d %s" % (v, sz, n))
        print("[emu] === 导出函数（.dynsym 已定义，可 --sym 调用）===")
        for n, v, x in img.dynsyms():
            if n and x != 0:
                print("  0x%08x  %s" % (v, n))
        print("[emu] === 导入函数（.dynsym, 未定义）===")
        print("  " + ", ".join(n for n, v, x in img.dynsyms() if not x and n))
        print("[emu] === PLT 桩 ===")
        for a, n in sorted(plt_ents.items()):
            print("  0x%08x  %s" % (a - base, n))
        return 0

    # --- 目标函数 ---
    func_addr = None
    if args.sym and img:
        cands = [(n, v, x) for (n, v, x, *_r) in img.symtab() if n == args.sym and x != 0]
        if not cands:
            cands = [(n, v, x) for (n, v, x) in img.dynsyms() if n == args.sym and x != 0]
        if not cands:
            subs = [(n, v, x) for (n, v, x, *_r) in img.symtab() if args.sym in n and x != 0]
            subs += [(n, v, x) for (n, v, x) in img.dynsyms() if args.sym in n and x != 0]
            if len(subs) == 1:
                cands = subs
                log("[emu] --sym 精确未命中，按子串取 %s" % subs[0][0])
            elif subs:
                log("[emu] --sym 不唯一，候选：%s" % ", ".join(sorted(set(s[0] for s in subs))[:20]))
                return 2
        if not cands:
            log("[emu] 找不到符号 %s（试 --list）" % args.sym)
            return 2
        func_addr = base + cands[0][1]
    elif args.func:
        func_addr = base + int(args.func, 16)
    elif args.raw:
        func_addr = base
    else:
        log("[emu] 需要 --sym 或 --func")
        return 2

    # --- 参数 ---
    cura = SCRATCH
    regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
            UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
    desc = []
    if args.arg_mode == "cstr":
        for i, a in enumerate(args.arg[:1]):
            raw = a.encode("utf-8", "replace") + b"\x00"
            uc.mem_write(cura, raw)
            uc.reg_write(UC_ARM64_REG_X0, cura)
            desc.append("x0=cstr@%s(%r)" % (hex(cura), a))
            cura = (cura + len(raw) + 15) & ~15
    elif args.arg_mode == "ptr_len":
        for i, a in enumerate(args.arg[:1]):
            raw = a.encode("utf-8", "replace")
            uc.mem_write(cura, raw + b"\x00")
            uc.reg_write(UC_ARM64_REG_X0, cura)
            uc.reg_write(UC_ARM64_REG_X1, len(raw))
            desc.append("x0=ptr@%s x1=len=%d(%r)" % (hex(cura), len(raw), a))
            cura = (cura + len(raw) + 16) & ~15
    elif args.arg_mode == "int":
        for i, a in enumerate(args.arg[:1]):
            v = int(a, 0)
            uc.reg_write(UC_ARM64_REG_X0, v & 0xFFFFFFFFFFFFFFFF)
            desc.append("x0=%d" % v)
    elif args.arg_mode == "ints":
        for i, a in enumerate(args.arg[:8]):
            v = int(a, 0)
            uc.reg_write(regs[i], v & 0xFFFFFFFFFFFFFFFF)
            desc.append("x%d=%d" % (i, v))
    elif args.arg_mode in ("jni_str", "jni_mix"):
        # x0 = JNIEnv*（假环境），x1 = jobject(0)，x2.. = jstring / 立即数 / null
        uc.reg_write(UC_ARM64_REG_X0, ENV_PTR)
        uc.reg_write(UC_ARM64_REG_X1, 0)
        desc.append("x0=ENV_PTR(假JNIEnv)")
        slot = 2
        for a in args.arg[:6]:
            if a.startswith("i:"):
                v = int(a[2:], 0)
                desc.append("x%d=%d" % (slot, v))
            elif a.startswith("n:"):
                v = 0
                desc.append("x%d=null" % slot)
            else:
                s = a[2:] if a.startswith("s:") else a
                raw = s.encode("utf-8", "replace") + b"\x00"
                uc.mem_write(cura, raw)
                v = cura
                desc.append("x%d=jstr@%s(%r)" % (slot, hex(cura), s))
                cura = (cura + len(raw) + 15) & ~15
            uc.reg_write(regs[slot], v & 0xFFFFFFFFFFFFFFFF)
            slot += 1

    # --- patch ---
    for p in args.patch:
        addr_s, hex_s = p.split(":", 1)
        addr = base + int(addr_s, 16)
        raw = bytes.fromhex(hex_s)
        try:
            uc.mem_write(addr, raw)
        except UcError:
            log("[-] patch 失败：0x%x 未映射。--patch 填 IDA 里看到的文件内地址（脚本自会加 base 0x%x），别重复加。"
                % (addr, base))
            return 2
        log("[emu] patch %s (+base=0x%x) ← %s" % (addr_s, addr, hex_s))

    # --- 运行 ---
    jni = JniEmu(uc, log)
    state = dict(insn=0, stop=None, fault=None, t0=time.time())
    last = []

    def hook_code(uc_, addr, size, _ud):
        state["insn"] += 1
        if len(last) == 0 or last[-1] != addr:
            last.append(addr)
            if len(last) > 64:
                last.pop(0)
        if addr == MAGIC_LR:
            state["stop"] = "ret"
            uc_.emu_stop()
            return
        if addr in plt_ents:
            name = plt_ents[addr]
            # 依赖库有真实实现（且非我们优先模拟的基础 libc）→ 直接跳到真实代码执行
            if name in dep_exports and name not in libc.table:
                uc_.reg_write(UC_ARM64_REG_PC, dep_exports[name])
                return
            try:
                ret = libc.call(name)
            except SystemExit as se:
                state["stop"] = str(se) or "stack_chk_fail"
                uc_.emu_stop()
                return
            except Exception:
                ret = 0
            # 未模拟的导入若走 AAPCS 的 sret（x8 = 返回对象缓冲），先清零缓冲，
            # 避免调用方把栈垃圾当作对象字段（会伪装成神秘崩溃）
            if name not in libc.table and name not in dep_exports:
                x8v = uc_.reg_read(UC_ARM64_REG_X8)
                if STACK <= x8v < STACK + STACK_SZ or HEAP <= x8v < HEAP + HEAP_SZ \
                        or SCRATCH <= x8v < SCRATCH + SCRATCH_SZ:
                    try:
                        uc_.mem_write(x8v, b"\x00" * 32)
                    except Exception:
                        pass
            uc_.reg_write(UC_ARM64_REG_X0, ret & 0xFFFFFFFFFFFFFFFF)
            uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))
            return
        if addr in jni.stubs:
            ret = jni.call(jni.stubs[addr])
            uc_.reg_write(UC_ARM64_REG_X0, ret & 0xFFFFFFFFFFFFFFFF)
            uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))
            return
        if addr == unknown_stub:
            state["stop"] = "unknown_import"
            uc_.emu_stop()
            return
        if args.trace:
            if state["insn"] < 400 and MD:
                code = uc_.mem_read(addr, min(size, 16))
                for ins in MD.disasm(bytes(code), addr):
                    print("  %08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
                    break
        if state["insn"] > args.max_insn or time.time() - state["t0"] > args.timeout:
            state["stop"] = "timeout"
            uc_.emu_stop()

    def hook_intr(uc_, intno, _ud):
        x8 = uc_.reg_read(UC_ARM64_REG_X8)
        x0 = uc_.reg_read(UC_ARM64_REG_X0)
        x1 = uc_.reg_read(UC_ARM64_REG_X1)
        x2 = uc_.reg_read(UC_ARM64_REG_X2)
        ret = None
        if x8 == 64:  # write
            data = bytes(uc_.mem_read(x1, min(x2, 4096))) if x1 else b""
            if x0 in (1, 2):
                log("[sys] write(%d): %r" % (x0, data[:200]))
            ret = x2
        elif x8 in (93, 94):  # exit
            state["stop"] = "exit"
            state["exit_code"] = x0
            uc_.emu_stop()
            return
        elif x8 == 63:  # read
            ret = -1 & 0xFFFFFFFFFFFFFFFF
        elif x8 == 318:  # getrandom
            uc_.mem_write(x0, b"\x00" * x1)
            ret = x1
        elif x8 == 113:  # clock_gettime
            if x1:
                uc_.mem_write(x1, struct.pack("<qq", 1700000000, 0))
            ret = 0
        elif x8 == 169:  # gettimeofday
            if x0:
                uc_.mem_write(x0, struct.pack("<qq", 1700000000, 0))
            ret = 0
        elif x8 == 222:  # mmap
            ret = libc._heap
            libc._heap = (libc._heap + x1 + PAGE) & ~(PAGE - 1)
        elif x8 in (226, 215):  # mprotect / munmap
            ret = 0
        elif x8 == 96:  # set_tid_address
            ret = 1234
        elif x8 == 98:  # futex
            ret = 0
        elif x8 == 172:  # getpid
            ret = 1234
        elif x8 == 178:  # gettid
            ret = 1234
        else:
            log("[sys] 未模拟 syscall %d → -ENOSYS（结果可能失真）" % x8)
            ret = -38 & 0xFFFFFFFFFFFFFFFF
        if ret is not None:
            uc_.reg_write(UC_ARM64_REG_X0, ret)
        uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_PC) + 4)

    def hook_unmapped(uc_, access, addr, size, value, _ud):
        state["fault"] = "unmapped %s @0x%x" % (
            {1: "READ", 2: "WRITE", 16: "FETCH"}.get(access, str(access)), addr)
        uc_.emu_stop()
        return False

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_intr)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    log("[emu] entry=%s base=0x%x %s" % (hex(func_addr), base, " ".join(desc) or "(无参数)"))
    try:
        uc.emu_start(func_addr, MAGIC_LR, timeout=0, count=args.max_insn)
    except UcError as e:
        state["fault"] = state["fault"] or str(e)

    w0 = uc.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    if state["stop"] is None and not state["fault"] and uc.reg_read(UC_ARM64_REG_PC) == MAGIC_LR:
        state["stop"] = "ret"
    stop = state["stop"] or state["fault"] or "?"
    print("[emu] STOP reason=%s insns=%d w0=0x%x (%d) x0=0x%x"
          % (stop, state["insn"], w0, w0, x0))
    if state["stop"] == "stack_chk_fail":
        print("[emu] __stack_chk_fail 被调用 → 该函数依赖 TLS/canary，结果不可信")
    if last:
        print("[emu] 故障/结束点前最后执行的一批指令：")
        for a in last[-14:]:
            txt = ""
            if MD:
                try:
                    for ins in MD.disasm(bytes(uc.mem_read(a, 4)), a):
                        txt = "%-8s %s" % (ins.mnemonic, ins.op_str)
                except Exception:
                    txt = "(不可读)"
            print("  %08x  %s" % (a, txt))
        print("[emu] 寄存器：x0..x7 = %s" % " ".join(
            hex(uc.reg_read(r)) for r in
            [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]))
    if libc.unknown_used:
        print("[emu] [!] 用到未模拟导入：%s" % ", ".join(sorted(libc.unknown_used)))
    if jni.unknown:
        print("[emu] [!] 用到未模拟 JNIEnv 函数编号：%s（结果可能失真）" % sorted(jni.unknown))
    for spec in args.dump:
        regn, lenn = spec.split(":")
        reg = {"x0": UC_ARM64_REG_X0, "x1": UC_ARM64_REG_X1,
               "x2": UC_ARM64_REG_X2, "x3": UC_ARM64_REG_X3}.get(regn.lower())
        ln = int(lenn)
        if reg:
            p = uc.reg_read(reg)
            data = bytes(uc.mem_read(p, ln)) if p else b""
            print("[emu] dump %s@0x%x (%d): %s | %s" % (
                regn, p, ln, data.hex(),
                data.decode("utf-8", "replace")))

    if state["fault"]:
        print("[-] 仿真故障：%s（可能是函数依赖真实环境/加密初始化，见 references/unicorn-emu.md 局限节）"
              % state["fault"])
        return 4
    if args.expect is not None and w0 != args.expect:
        print("[-] --expect %d 不符（实际 w0=%d）→ 退出码 3" % (args.expect, w0))
        return 3
    print("[+] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
