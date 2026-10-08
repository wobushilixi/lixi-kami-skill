#!/usr/bin/env python3
"""jsrpc_server.py - JSRPC：把真实浏览器当"签名/加密计算器"（Web 逆向的保底打法）

为什么要它（来自 590⭐ skill 的实战方案）：
    签名算法还原不出来 / 补环境补不对时，**不必死磕算法**——让真实浏览器继续算：
    页面里注入一段客户端 JS → 通过 WebSocket 接受本地指令 → 调用页面里的真实函数
    → 把结果回传。本地 Python 就能随时拿到合法签名/密文，用来重放、批量、mock、Burp。

架构:
    [浏览器页面]  ← 注入 jsrpc_client.js，连 ws://127.0.0.1:PORT
         ↑↓
    [本脚本 serve]  ← 中继（browser 端 + ctl 端两种角色）
         ↑↓
    [本脚本 call/eval]  ← 命令行发起调用（或 import 当库用）

用法（三步）:
    1) 起服务（后台）:   python jsrpc_server.py serve --port 19090
    2) 注入客户端:       用 js-reverse-mcp / chrome-devtools 的 evaluate_script
                        注入 templates/jsrpc_client.js 的内容（整段 IIFE）
                        → 控制台/返回值出现 {"role":"browser","exposed":[...]}
    3) 调用:             python jsrpc_server.py call eval "return window.someSign('a=1')"
                         python jsrpc_server.py call sign '["a=1","b=2"]'
                         python jsrpc_server.py list          # 看已暴露的函数
                         python jsrpc_server.py ping          # 看浏览器是否在线

客户端内置能力（注入后即可用）:
    __jsrpc.eval(code)               任意 JS（函数体，用 return 返回值）
    __jsrpc.expose(name, fn)         把页面函数暴露给本地
    __jsrpc.wrap("CryptoJS.AES","encrypt")   包一层对象方法（原方法照常工作）
    __jsrpc.wrapAll("CryptoJS")      扫一层对象的所有函数
    __jsrpc.exposed()                当前已暴露列表

注意: 仅连 127.0.0.1；不对外开放端口。浏览器页面刷新后客户端会掉，重新注入即可。
"""

import argparse
import asyncio
import json
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import websockets
    from websockets.asyncio.server import serve as ws_serve
    from websockets.asyncio.client import connect as ws_connect
except Exception as e:  # 兼容旧版 API
    print("[-] websockets 不可用:", e)
    sys.exit(2)

DEFAULT_PORT = 19090


class Relay:
    """中继：browser 端与 ctl 端之间转发调用。"""

    def __init__(self, verbose=True):
        self.browsers = {}   # id -> websocket
        self.ctl = {}
        self.pending = {}    # call_id -> (future, ctl_ws)
        self.next_id = 1
        self.verbose = verbose
        self.exposed = []    # 最近一个 browser 上报暴露的函数
        self._lock = asyncio.Lock()

    async def handler(self, ws):
        role = None
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                t = msg.get("type")
                if t == "hello":
                    role = msg.get("role", "browser")
                    if role == "browser":
                        self.browsers[id(ws)] = ws
                        self.exposed = msg.get("exposed", [])
                        if self.verbose:
                            print("[+] 浏览器已连接 exposed=%s" % self.exposed)
                    else:
                        self.ctl[id(ws)] = ws
                        if self.verbose:
                            print("[+] 控制端已连接")
                    await ws.send(json.dumps({"type": "welcome",
                                              "browsers": len(self.browsers)}))
                elif t == "call" and role == "ctl":
                    # ctl 发起的调用 → 转发给浏览器
                    if not self.browsers:
                        await ws.send(json.dumps({"type": "result", "id": msg.get("id"),
                                                  "ok": False,
                                                  "error": "无浏览器连接（先注入客户端）"}))
                        continue
                    async with self._lock:
                        cid = self.next_id
                        self.next_id += 1
                    self.pending[cid] = (ws, msg.get("id"))
                    bid, bws = next(iter(self.browsers.items()))
                    await bws.send(json.dumps({"type": "call", "id": cid,
                                               "fn": msg.get("fn"), "args": msg.get("args", [])}))
                elif t == "result":
                    # 浏览器回结果 → 还给对应 ctl
                    entry = self.pending.pop(msg.get("id"), None)
                    if entry:
                        ctl_ws, ctl_id = entry
                        await ctl_ws.send(json.dumps({"type": "result", "id": ctl_id,
                                                      "ok": msg.get("ok"),
                                                      "result": msg.get("result"),
                                                      "error": msg.get("error")}))
                elif t == "list" and role == "ctl":
                    await ws.send(json.dumps({"type": "result", "id": msg.get("id"),
                                              "ok": True,
                                              "result": {"browsers": len(self.browsers),
                                                         "exposed": self.exposed}}))
        finally:
            if role == "browser":
                self.browsers.pop(id(ws), None)
                if self.verbose:
                    print("[!] 浏览器断开")
            else:
                self.ctl.pop(id(ws), None)


async def cmd_serve(port, verbose=True):
    relay = Relay(verbose)
    async with ws_serve(relay.handler, "127.0.0.1", port):
        print("[jsrpc] 服务已启动 ws://127.0.0.1:%d" % port)
        print("[jsrpc] 下一步：把 templates/jsrpc_client.js 注入浏览器页面")
        await asyncio.Future()   # 常驻


async def cmd_call(port, fn, args, timeout):
    try:
        ws = await ws_connect("ws://127.0.0.1:%d" % port)
    except Exception as e:
        print("[-] 连不上中继服务（ws://127.0.0.1:%d）：%s" % (port, e))
        print("    先启动：python scripts/jsrpc_server.py serve --port %d" % port)
        return 3
    async with ws:
        await ws.send(json.dumps({"type": "hello", "role": "ctl"}))
        await ws.recv()  # welcome
        if fn == "__list__":
            await ws.send(json.dumps({"type": "list", "id": 1}))
        else:
            await ws.send(json.dumps({"type": "call", "id": 1, "fn": fn, "args": args}))
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            print("[-] 超时（浏览器没响应？确认客户端已注入且页面存活）")
            return 3
        msg = json.loads(raw)
        if msg.get("ok"):
            r = msg.get("result")
            print(json.dumps(r, ensure_ascii=False) if not isinstance(r, str) else r)
            return 0
        print("[-] 调用失败:", msg.get("error"))
        return 1


def main():
    ap = argparse.ArgumentParser(description="JSRPC：真实浏览器当签名计算器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("serve", help="启动中继服务（常驻）")
    p1.add_argument("--port", type=int, default=DEFAULT_PORT)

    p2 = sub.add_parser("call", help="调用浏览器里已暴露的函数")
    p2.add_argument("fn", help="函数名（或 eval / __list__）")
    p2.add_argument("args", nargs="?", default="[]", help="JSON 数组参数")
    p2.add_argument("--port", type=int, default=DEFAULT_PORT)
    p2.add_argument("--timeout", type=int, default=30)

    p3 = sub.add_parser("eval", help="在浏览器里执行任意 JS（函数体，用 return 返回）")
    p3.add_argument("code")
    p3.add_argument("--port", type=int, default=DEFAULT_PORT)
    p3.add_argument("--timeout", type=int, default=30)

    p4 = sub.add_parser("list", help="查看浏览器连接与已暴露函数")
    p4.add_argument("--port", type=int, default=DEFAULT_PORT)

    p5 = sub.add_parser("ping", help="探活")
    p5.add_argument("--port", type=int, default=DEFAULT_PORT)

    args = ap.parse_args()

    if args.cmd == "serve":
        asyncio.run(cmd_serve(args.port))
    elif args.cmd == "call":
        try:
            argv = json.loads(args.args)
        except Exception:
            print("[-] args 需要 JSON 数组，如 '[\"a=1\"]'")
            return 2
        return asyncio.run(cmd_call(args.port, args.fn, argv, args.timeout))
    elif args.cmd == "eval":
        return asyncio.run(cmd_call(args.port, "eval", [args.code], args.timeout))
    elif args.cmd == "list":
        return asyncio.run(cmd_call(args.port, "__list__", [], 10))
    elif args.cmd == "ping":
        try:
            return asyncio.run(cmd_call(args.port, "__list__", [], 5))
        except Exception as e:
            print("[-] 服务未启动或不可达:", e)
            return 1


if __name__ == "__main__":
    sys.exit(main())
