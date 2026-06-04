#!/usr/bin/env python3
"""
IShield 三类攻击场景 — 一键红队执行

依次运行三个场景的智能体攻击脚本，汇总拦截成功率。

用法（需先启动 backend: python app.py）:
  python attacks/run_all_attacks.py
  python attacks/run_all_attacks.py --api http://127.0.0.1:5000 --count 500
  python attacks/case_generator.py --count 500 --save   # 预生成 cases.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UTC8 = timezone(timedelta(hours=8))

SCRIPTS = [
    ("scenario1_prompt_injection/attack_agent.py", "场景一：提示注入与越狱"),
    ("scenario2_tool_hijacking/attack_agent.py", "场景二：工具调用劫持"),
    ("scenario3_memory_poisoning/attack_agent.py", "场景三：记忆中毒"),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api", default="http://127.0.0.1:5000")
    p.add_argument("--count", type=int, default=500, help="每场景生成用例数")
    p.add_argument("--use-file", action="store_true", help="各场景使用 cases.json")
    args = p.parse_args()

    reports_dir = os.path.join(ROOT, "attacks", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    summary = {
        "generated_at": datetime.now(UTC8).strftime("%Y-%m-%d %H:%M:%S"),
        "backend": args.api,
        "scenarios": [],
    }

    print("=" * 60)
    print("IShield 三类攻击场景 — 红队总控")
    print("=" * 60)

    for rel, title in SCRIPTS:
        script = os.path.join(ROOT, "attacks", rel)
        out_name = os.path.basename(os.path.dirname(rel)) + "_report.json"
        out_path = os.path.join(reports_dir, out_name)

        print(f"\n>>> 运行 {title}")
        cmd = [sys.executable, script, "--api", args.api, "--output", out_path, "--count", str(args.count)]
        if args.use_file:
            cmd.append("--use-file")
        rc = subprocess.call(cmd, cwd=ROOT)
        if os.path.isfile(out_path):
            with open(out_path, encoding="utf-8") as f:
                rep = json.load(f)
            summary["scenarios"].append(
                {
                    "name": title,
                    "report": out_path,
                    "total": rep.get("total"),
                    "blocked": rep.get("blocked"),
                    "block_rate_pct": rep.get("block_rate_pct"),
                    "exit_code": rc,
                }
            )

    total_all = sum(s.get("total") or 0 for s in summary["scenarios"])
    blocked_all = sum(s.get("blocked") or 0 for s in summary["scenarios"])
    summary["overall"] = {
        "total": total_all,
        "blocked": blocked_all,
        "block_rate_pct": round(blocked_all / total_all * 100, 2) if total_all else 0,
    }

    master_path = os.path.join(reports_dir, "all_scenarios_summary.json")
    with open(master_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 60)
    print("总控汇总")
    print("=" * 60)
    for s in summary["scenarios"]:
        print(f"  {s['name']}: {s['block_rate_pct']}% ({s['blocked']}/{s['total']})")
    print(f"\n  总体拦截率: {summary['overall']['block_rate_pct']}%")
    print(f"  汇总报告: {master_path}")


if __name__ == "__main__":
    main()
