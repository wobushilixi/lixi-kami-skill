#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
案件建档（对齐 references/evidence-case-conventions.md）
======================================================
创建一个可复现的案件目录骨架：身份信息、证据分区、E# 假设台账、parity 夹具、
失败台账与报告模板。所有后续产物都往这个骨架里落，交付时自然齐活。

用法：
  python init_case.py my-target                      # -> cases/my-target/
  python init_case.py my-target --out D:\\cases --sha256 <hex> --target-type apk
"""
import argparse
import datetime
import os
import re


def safe_name(name):
    s = re.sub(r"[^\w\u4e00-\u9fff\-]+", "-", name.strip())
    return s.strip("-") or "case"


CASE_YAML = """# 案件身份（DoD ①：目标已确认）
case_id: {cid}
created: {date}
target: {name}
target_type: unknown      # apk / dex / so / exe / web / har / pcap / other
size_bytes: null
sha256: {sha}
version: null
objective: 绕过卡密并验证功能放行
stop_loss: 连续 2 次无证据支撑的失败 → 回 S1
"""

TIMELINE = """# 时间线

| 时间 | 动作 | 观察 | 证据（文件/地址/请求） | 关联 E# |
|---|---|---|---|---|
|  |  |  |  |  |
"""

HYPOTHESES = """# E# 假设台账

> 每条写清楚：假设 → 依据 → 验证方式 → 结算（S4 时逐条写「已证实 / 已推翻 / 仍未知」）

## E1
- 假设：
- 依据：（扫描命中 / 反汇编地址 / 抓包字段 / 字符串交叉引用）
- 验证方式：（哪条命令 / 看什么输出）
- 状态：待验证

## E2
- 假设：
- 依据：
- 验证方式：
- 状态：待验证
"""

REPORT = """# {name} 分析报告

## 一句话结论
（能不能绕过 / 卡在哪 / 需要什么才能确定）

## 目标身份
name / size / SHA256 / 类型 / 版本 / 获取来源

## 保护与对抗层
壳（类型 + 置信度 + 证据）｜签名校验｜反调试｜环境检测｜结论：影响哪一步

## 证据
| # | 证据 | 来源 | 支持哪条 E# | 状态 |
|---|---|---|---|---|
|  |  |  |  |  |

## 技术链路
入口 → 加载/解密 → 判定 → 放行/拦截

## 复现
（命令 / 脚本 / 夹具，能一键重跑）

## 局限与未验证项
（真机未测 / 无有效样本 / 只覆盖某版本 —— 必须如实写）

## 下一步
（需要什么输入 / 跑哪条命令 / 看哪条输出）
"""

FAILURES = "target\tstage\tcode\tdetail\tdate\n"


def main():
    ap = argparse.ArgumentParser(description="创建案件目录骨架")
    ap.add_argument("name")
    ap.add_argument("--out", default="cases", help="案件根目录（默认 cases/）")
    ap.add_argument("--sha256", default="null")
    args = ap.parse_args()

    cid = safe_name(args.name)
    root = os.path.join(args.out, cid)
    for rel in ("evidence/raw", "evidence/derived", "notes", "repro", "tests"):
        os.makedirs(os.path.join(root, rel), exist_ok=True)
    today = datetime.date.today().isoformat()
    with open(os.path.join(root, "case.yaml"), "w", encoding="utf-8") as f:
        f.write(CASE_YAML.format(cid=cid, date=today, name=args.name, sha=args.sha256))
    with open(os.path.join(root, "notes", "timeline.md"), "w", encoding="utf-8") as f:
        f.write(TIMELINE)
    with open(os.path.join(root, "notes", "hypotheses.md"), "w", encoding="utf-8") as f:
        f.write(HYPOTHESES)
    with open(os.path.join(root, "report.md"), "w", encoding="utf-8") as f:
        f.write(REPORT.format(name=args.name))
    with open(os.path.join(root, "failures.tsv"), "w", encoding="utf-8") as f:
        f.write(FAILURES)
    open(os.path.join(root, "tests", "fixtures.jsonl"), "w", encoding="utf-8").close()
    open(os.path.join(root, "manifest.json"), "w", encoding="utf-8").close()
    open(os.path.join(root, "evidence", "raw", ".gitkeep"), "w", encoding="utf-8").close()
    open(os.path.join(root, "evidence", "derived", ".gitkeep"), "w", encoding="utf-8").close()

    print(root)
    print("骨架: case.yaml / notes/{timeline,hypotheses}.md / report.md / failures.tsv")
    print("      evidence/raw(只读) / evidence/derived / repro/ / tests/fixtures.jsonl / manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
