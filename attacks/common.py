"""IShield 红队攻击脚本 — 公共工具"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

UTC8 = timezone(timedelta(hours=8))
ATTACKS_ROOT = os.path.dirname(os.path.abspath(__file__))


def load_cases(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def http_post(url: str, payload: dict, timeout: float = 30) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class AttackOutcome:
    case_id: str
    scenario: str
    attack_type: str
    payload_preview: str
    blocked: bool
    channel: str  # detect | simulate | chain
    detail: str
    elapsed_ms: float
    raw: Optional[dict] = None


class Reporter:
    def __init__(self, scenario: str, backend: str):
        self.scenario = scenario
        self.backend = backend
        self.results: List[AttackOutcome] = []
        self.started = datetime.now(UTC8)

    def add(self, outcome: AttackOutcome):
        self.results.append(outcome)

    def summary(self) -> dict:
        total = len(self.results)
        blocked = sum(1 for r in self.results if r.blocked)
        return {
            "scenario": self.scenario,
            "backend": self.backend,
            "started_at": self.started.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": datetime.now(UTC8).strftime("%Y-%m-%d %H:%M:%S"),
            "total": total,
            "blocked": blocked,
            "escaped": total - blocked,
            "block_rate_pct": round(blocked / total * 100, 2) if total else 0.0,
            "results": [asdict(r) for r in self.results],
        }

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.summary(), f, ensure_ascii=False, indent=2)

    def print_summary(self):
        s = self.summary()
        print()
        print("=" * 60)
        print(f"场景: {s['scenario']}")
        print(f"攻击总数: {s['total']}  拦截: {s['blocked']}  逃逸: {s['escaped']}")
        print(f"拦截成功率: {s['block_rate_pct']}%")
        escaped = [r for r in self.results if not r.blocked]
        if escaped:
            print("\n逃逸样本:")
            for r in escaped[:10]:
                print(f"  - {r.case_id} [{r.attack_type}] {r.payload_preview[:50]}...")


def detect_attack(backend: str, text: str) -> tuple[bool, str, dict, float]:
    t0 = time.perf_counter()
    try:
        resp = http_post(f"{backend.rstrip('/')}/api/detect", {"text": text})
        if not resp.get("success", True):
            return False, resp.get("message", "API 错误"), {}, (time.perf_counter() - t0) * 1000
        data = resp.get("data", {})
        blocked = data.get("status") == "malicious"
        reason = data.get("reason", "")
        return blocked, reason, data, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: 服务端错误（非逃逸，请查 backend/logs）", {}, (time.perf_counter() - t0) * 1000
    except urllib.error.URLError as e:
        return False, f"连接失败: {e}", {}, (time.perf_counter() - t0) * 1000


def simulate_tool(backend: str, action: str, params: str) -> tuple[bool, str, dict, float]:
    t0 = time.perf_counter()
    try:
        resp = http_post(
            f"{backend.rstrip('/')}/api/simulate",
            {"action": action, "params": params},
        )
        data = resp.get("data", {})
        result = data.get("result", "")
        blocked = result in ("blocked",)
        reason = data.get("reason", result)
        return blocked, reason, data, (time.perf_counter() - t0) * 1000
    except urllib.error.URLError as e:
        return False, f"连接失败: {e}", {}, (time.perf_counter() - t0) * 1000
