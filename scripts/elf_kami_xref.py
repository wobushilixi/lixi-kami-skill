#!/usr/bin/env python3
"""
aarch64 ELF 卡密判定点分析器（capstone 版）
用途：strip/OLLVM 混淆的 Android ELF 目标，定位 PLT 调用点 -> 反向找判定分支。
作者：逆向分析工作流

用法：
  python elf_kami_xref.py <elf> --plt fopen,strcmp,fread [--text-sec auto] [--context N]
"""
import struct, sys, argparse, collections
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SHT_SYMTAB, SHT_DYNSYM, SHT_RELA, SHT_RELASYM, SHT_STRTAB = 2, 11, 4, 9, 3


class Elf64:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        d = self.d
        if d[:4] != b'\x7fELF':
            raise ValueError('not ELF64')
        self.machine = struct.unpack_from('<H', d, 18)[0]
        if self.machine != 0xb7:
            raise ValueError('only aarch64, got 0x%x' % self.machine)
        self.shoff = struct.unpack_from('<Q', d, 0x28)[0]
        self.shentsize = struct.unpack_from('<H', d, 0x3a)[0]
        self.shnum = struct.unpack_from('<H', d, 0x3c)[0]
        self.shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
        self.sections = [self._sh(i) for i in range(self.shnum)]
        self.by_name = {self._name(s['name']): s for s in self.sections}

    def _sh(self, i):
        o = self.shoff + i * self.shentsize
        f = struct.unpack_from('<IIQQQQIIQQ', self.d, o)
        return dict(idx=i, name=f[0], typ=f[1], flags=f[2], addr=f[3],
                    off=f[4], size=f[5], link=f[6], info=f[7], align=f[8], entsize=f[9])

    def _name(self, x):
        b = self.sections[self.shstrndx]['off'] + x
        return self.d[b:self.d.index(b'\0', b)].decode('utf8', 'replace')

    def cstr(self, base):
        e = self.d.index(b'\0', base)
        return self.d[base:e].decode('utf8', 'replace')

    def sec_data(self, name):
        s = self.by_name.get(name)
        return None if s is None else self.d[s['off']:s['off'] + s['size']]

    def vaddr_to_off(self, va):
        for s in self.sections:
            if s['addr'] and s['addr'] <= va < s['addr'] + s['size'] and s['typ'] != 8:
                return s['off'] + (va - s['addr'])
        return None

    def symbols(self):
        """返回 {name: (value, size, type, bind)} from .symtab/.dynsym"""
        out = {}
        for sec in self.sections:
            if sec['typ'] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            strtab = self.sections[sec['link']] if sec['link'] < len(self.sections) else None
            if not strtab:
                continue
            es = sec['entsize'] or 24
            n = sec['size'] // es
            for k in range(n):
                o = sec['off'] + k * es
                no, info, other, shnd, val, sz = struct.unpack_from('<IBBHQQ', self.d, o)
                if no == 0:
                    continue
                try:
                    nm = self.cstr(strtab['off'] + no)
                except Exception:
                    continue
                if nm and nm not in out:
                    out[nm] = (val, sz, info & 0xf, info >> 4)
        return out

    def plt_map(self):
        """返回 {funcname: plt_stub_vaddr}，通过 .rela.plt + .plt 结构计算"""
        res = {}
        rela = self.by_name.get('.rela.plt') or self.by_name.get('.rel.plt')
        plt = self.by_name.get('.plt')
        if not rela or not plt:
            return res
        syms = {}
        for sec in self.sections:
            if sec['typ'] in (SHT_SYMTAB, SHT_DYNSYM):
                strtab = self.sections[sec['link']]
                es = sec['entsize'] or 24
                for k in range(sec['size'] // es):
                    o = sec['off'] + k * es
                    no, info, other, shnd, val, sz = struct.unpack_from('<IBBHQQ', self.d, o)
                    if no:
                        try:
                            syms[k if sec['typ'] == SHT_DYNSYM else (val, sz)] = self.cstr(strtab['off'] + no)
                        except Exception:
                            pass
        dynsym = next((s for s in self.sections if s['name'] == self.sections[self.shstrndx]['name'] and s['typ'] == SHT_DYNSYM), None)
        # 直接用 dynsym 索引
        dsym = None
        for sec in self.sections:
            if sec['typ'] == SHT_DYNSYM:
                dsym = sec
                break
        if not dsym:
            return res
        strtab = self.sections[dsym['link']]
        es = dsym['entsize'] or 24
        esize = rela['entsize'] or 24
        # aarch64 .plt: 前 0x20 字节是 PLT0，之后每项 0x10
        hdr = 0x20 if plt['size'] > 0x20 else 0
        step = 0x10
        for i in range(rela['size'] // esize):
            o = rela['off'] + i * esize
            r_off, r_info, r_add = struct.unpack_from('<QQq', self.d, o)
            symidx = r_info >> 32
            no = struct.unpack_from('<I', self.d, dsym['off'] + symidx * es)[0]
            try:
                nm = self.cstr(strtab['off'] + no)
            except Exception:
                continue
            stub = plt['addr'] + hdr + i * step
            res.setdefault(nm, stub)
        return res


def analyze(path, targets, context=6, textsec='.text'):
    e = Elf64(path)
    plt = e.plt_map()
    print('[*] %s  size=%d  machine=aarch64' % (path, len(e.d)))
    ts = e.by_name.get(textsec)
    if not ts:
        ts = next((s for s in e.sections if s['name'] and s['addr'] and s['size'] > 0x1000 and s['typ'] == 1), None)
    if not ts:
        print('[!] no text section'); return
    print('[+] .text @0x%x size=0x%x' % (ts['addr'], ts['size']))

    want = {}
    for t in targets:
        for name, stub in plt.items():
            if name == t or name.startswith(t):
                want[stub] = name
    if not want:
        print('[!] none of targets %s found in PLT' % targets)
        print('    available sample:', ', '.join(sorted(plt)[:40]))
        return
    print('[+] tracking PLT stubs:')
    for stub, nm in sorted(want.items(), key=lambda x: x[0]):
        print('    %-24s @0x%x' % (nm, stub))

    code = e.d[ts['off']:ts['off'] + ts['size']]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    # 反汇编并记录 BL 目标
    calls = collections.defaultdict(list)
    insns = list(md.disasm(code, ts['addr']))
    for ins in insns:
        if ins.mnemonic in ('bl', 'b') and ins.op_str.startswith('#'):
            try:
                tgt = int(ins.op_str[1:], 0)
            except ValueError:
                continue
            if tgt in want:
                calls[tgt].append(ins.address)
    for stub, nm in sorted(want.items(), key=lambda x: x[0]):
        sites = calls.get(stub, [])
        print('\n[=] %s (%s): %d call site(s)' % (nm, hex(stub), len(sites)))
        for sa in sites:
            print('    caller @0x%x' % sa)
    return e, ts, insns, want, calls


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('--plt', default='fopen,fread,strcmp,strncmp,memcmp,open')
    ap.add_argument('--text-sec', default='.text')
    ap.add_argument('--context', type=int, default=6)
    ap.add_argument('--dump', action='store_true', help='dump disasm around each call site')
    a = ap.parse_args()
    r = analyze(a.elf, a.plt.split(','), a.context, a.text_sec)
    if r and a.dump:
        e, ts, insns, want, calls = r
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        idx = {ins.address: i for i, ins in enumerate(insns)}
        for stub, sites in calls.items():
            for sa in sites:
                print('\n' + '=' * 70)
                print('  site 0x%x  (calls %s)' % (sa, want[stub]))
                i = idx[sa]
                for ins in insns[max(0, i - a.context): i + a.context + 2]:
                    mark = '>>' if ins.address == sa else '  '
                    print('  %s 0x%x  %-8s %s' % (mark, ins.address, ins.mnemonic, ins.op_str))