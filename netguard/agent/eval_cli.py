"""对抗式评测命令行入口。

## 用法

    # 用本地 Ollama 跑一份配置
    python -m netguard.agent.eval_cli corpus/case01_core_switch.txt --model qwen2.5:7b

    # 批量
    python -m netguard.agent.eval_cli corpus/*.txt --model qwen2.5:7b

    # 自检：模型是否支持 tools（M1—M5 依赖）
    python -m netguard.agent.eval_cli --probe --model qwen2.5:7b

## 为什么单独一个 CLI

M6 与巡检是两个目的：巡检产报告，评测产数字。混在一个入口里会让
「我只想看报告」的人被迫等模型跑完评测。分开之后，两边都能独立使用。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adversarial import adversarial_eval
from .llm import LLMError, OllamaClient

__all__ = ["main"]


def _run_one(client, path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    result = adversarial_eval(client, text, device_id=path.name)
    summary = result.summary()
    summary["_result"] = result
    return summary


def _print_one(path: Path, summary: dict, verbose: bool) -> None:
    result = summary.pop("_result")
    print(f"=== {path.name} ===")
    if not result.ok:
        print(f"  提议失败：{summary.get('error')}")
        print()
        return

    total = summary["claims"]
    valid = summary["valid_claims"]
    tp = summary["true_positives"]
    fn = summary["false_negatives"]
    print(f"  模型提出 {total} 条假设，其中成立 {valid} 条"
          f"（有效率 {valid / total:.2f}）" if total else "  模型未提出假设")
    print(f"  规则抓到 {tp} 条，漏报 {fn} 条"
          + (f"（召回率 {tp / valid:.2f}）" if valid else ""))
    if summary["unexplained"]:
        print(f"  规则报出但无假设指向：{summary['unexplained']} 条 → 待人工判定误报/漏标")

    if verbose:
        for rec in result.report.records:
            mark = "✓" if rec.hit else ("✗ 漏报" if rec.lookup.ok else "· 假设不成立")
            print(f"    {mark}  {rec.spec.kind:<22} {rec.spec.note or rec.lookup.detail}")
        if result.unmapped:
            print("    无法映射到规则的假设：")
            for p in result.unmapped:
                print(f"      - {p.kind}: {p.note}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netguard-eval",
        description="对抗式缺陷评测：模型提议 → 代码裁决 → 规则判定",
    )
    parser.add_argument("files", nargs="*", help="配置文件路径")
    parser.add_argument("--model", default="qwen2.5:7b", help="Ollama 模型名")
    parser.add_argument("--base-url", default="http://localhost:11434", help="Ollama 地址")
    parser.add_argument("--probe", action="store_true", help="只做模型工具支持自检")
    parser.add_argument("-v", "--verbose", action="store_true", help="逐条列出假设")
    args = parser.parse_args(argv)

    client = OllamaClient(args.model, base_url=args.base_url)

    if args.probe:
        ok = client.probe_tools()
        print(f"模型 {args.model} 的 tools 支持：{'是' if ok else '否'}")
        if not ok:
            print("  → M1—M5 无法运行；M6（对抗评测）不依赖 tools，仍可用")
            print("  → 建议换 qwen3:8b，或用 ollama show 检查 template 是否含 .Tools")
        return 0 if ok else 1

    if not args.files:
        parser.error("需要至少一个配置文件（或用 --probe 做自检）")

    paths = [Path(p) for p in args.files]
    missing = [p for p in paths if not p.exists()]
    if missing:
        for p in missing:
            print(f"文件不存在: {p}", file=sys.stderr)
        return 2

    summaries: list[dict] = []
    for p in paths:
        try:
            summary = _run_one(client, p)
        except LLMError as exc:
            print(f"=== {p.name} ===\n  模型调用失败：{exc}\n")
            continue
        summaries.append(summary)
        _print_one(p, summary, args.verbose)

    ok_summaries = [s for s in summaries if "error" not in s]
    if ok_summaries:
        total = sum(s["claims"] for s in ok_summaries)
        valid = sum(s["valid_claims"] for s in ok_summaries)
        tp = sum(s["true_positives"] for s in ok_summaries)
        print("=== 合计 ===")
        print(f"  配置 {len(ok_summaries)} 份，假设 {total} 条，成立 {valid} 条")
        if total:
            print(f"  假设有效率 {valid / total:.2f}")
        if valid:
            print(f"  召回率 {tp / valid:.2f}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
