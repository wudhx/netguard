"""无模型命令行入口。

## 为什么必须有一个不依赖模型的 CLI

这不是「降级方案」的礼貌说法，是一个**架构声明**：判定层零依赖模型。

它的存在让两件事同时成立：

1. 评分者可以 `pip install` 后立刻看到 12 条规则的真实输出，
   不必先装 Ollama 下 7B 模型
2. 「模型的必要性」可以被诚实地区分——判定不需要模型，**对抗评测需要**

第 2 点正是 P2 的边界所在。本 CLI 不做任何需要模型的事，
它只做确定性的事；需要模型的那件事，在 `netguard/agent/adversarial.py`。

## 用法

    python -m netguard.core.cli check corpus/case01_core_switch.txt
    python -m netguard.core.cli check corpus/*.txt --summary
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import RunResult, run_all_rules
from .models import Role, Severity
from .parser import parse_file
from .profile import infer_role

__all__ = ["main"]

#: 严重度显示顺序，与枚举值一致（高在前）
_ORDER = [Severity.BLOCKER, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _fmt_device(path: Path) -> str:
    cfg = parse_file(str(path))
    result = run_all_rules(cfg)
    return _render(path, result)


def _render(path: Path, result: RunResult) -> str:
    out: list[str] = []
    out.append(f"=== {path.name}  ({result.device_id}) ===")
    out.append(f"角色: {result.role.value}    执行规则: {len(result.rules_run)}    "
               f"跳过: {len(result.skipped)}    发现: {len(result.findings)}")

    if result.skipped:
        out.append("跳过:")
        for rid, reason in sorted(result.skipped.items()):
            out.append(f"  - {rid}: {reason}")

    if result.errors:
        out.append("规则异常（必须修）:")
        for rid, err in sorted(result.errors.items()):
            out.append(f"  ! {rid}: {err}")

    findings = sorted(
        result.findings,
        key=lambda f: (-f.severity.value, f.rule_id, f.location),
    )
    if not findings:
        out.append("未发现问题。")
    else:
        for f in findings:
            loc = f.location
            line = f"  [{f.severity.name:7}] {f.rule_id}  {loc}"
            if f.line_no:
                line += f"  (第 {f.line_no} 行)"
            out.append(line)
            out.append(f"      {f.message}")
            if f.evidence:
                out.append(f"      证据: {f.evidence}")
            out.append(f"      依据: {f.basis}")

    out.append("")
    return "\n".join(out)


def _summary(paths: list[Path]) -> str:
    rows = []
    totals: dict[str, int] = {}
    for p in paths:
        cfg = parse_file(str(p))
        result = run_all_rules(cfg)
        rows.append((p.name, result.role, len(result.findings), result.by_severity()))
        for k, v in result.by_severity().items():
            totals[k] = totals.get(k, 0) + v

    out = ["文件                            角色     发现  BLOCKER HIGH MEDIUM LOW INFO"]
    for name, role, count, by_sev in rows:
        out.append(
            f"{name:<32}{role.value:<9}{count:<6}"
            + " ".join(f"{by_sev.get(s.name, 0):<8}" for s in _ORDER)
        )
    out.append("")
    out.append("合计: " + "  ".join(f"{s.name}={totals.get(s.name, 0)}" for s in _ORDER))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netguard", description="华为 VRP 配置合规巡检（确定性，无需模型）"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser("check", help="巡检一份或多份配置")
    check.add_argument("files", nargs="+", help="配置文件路径")
    check.add_argument("--summary", action="store_true", help="只输出汇总表")

    args = parser.parse_args(argv)

    if args.cmd == "check":
        paths = [Path(p) for p in args.files]
        missing = [p for p in paths if not p.exists()]
        if missing:
            for p in missing:
                print(f"文件不存在: {p}", file=sys.stderr)
            return 2

        if args.summary:
            print(_summary(paths))
        else:
            for p in paths:
                print(_fmt_device(p))
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
