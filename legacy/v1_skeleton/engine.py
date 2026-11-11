"""规则引擎：遍历规则、执行判定、汇总结果。

引擎本身不含任何业务判断，只负责调度与异常隔离：
单条规则抛异常不会中断整体巡检，异常会转为一条 error 级发现项。
"""

from __future__ import annotations

from .models import Config, Finding
from .rules import RULES, Rule

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
LEVEL_ORDER = {"A": 0, "B": 1, "C": 2}


def run(cfg: Config, include_level_c: bool = True) -> list[Finding]:
    """对一份配置执行全部规则，返回排序后的发现项列表。"""
    findings: list[Finding] = []
    for rule in RULES:
        if rule.level == "C" and not include_level_c:
            continue
        try:
            result = rule.check(cfg)
        except Exception as exc:  # noqa: BLE001 - 规则隔离，不让单条规则拖垮整体
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=rule.category,
                    level=rule.level,
                    severity="error",
                    message=f"规则执行异常：{exc}",
                )
            )
            continue
        if result:
            findings.extend(result)
    return sort_findings(findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            LEVEL_ORDER.get(f.level, 9),
            SEVERITY_ORDER.get(f.severity, 9),
            f.rule_id,
            f.line_no,
        ),
    )


def hit_rule_ids(findings: list[Finding], levels: tuple[str, ...] = ("A", "B")) -> set[str]:
    """命中的规则编号集合（默认排除 C 级与执行异常项）。"""
    return {f.rule_id for f in findings if f.level in levels and f.severity != "error"}


def summarize(findings: list[Finding]) -> dict:
    """按等级与严重程度汇总。"""
    by_level: dict[str, int] = {"A": 0, "B": 0, "C": 0}
    by_severity: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0, "error": 0}
    rules_hit: set[str] = set()
    for f in findings:
        by_level[f.level] = by_level.get(f.level, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        rules_hit.add(f.rule_id)
    return {
        "total": len(findings),
        "by_level": by_level,
        "by_severity": by_severity,
        "rules_hit": sorted(rules_hit),
        "rule_count": len(rules_hit),
    }


def describe_rules() -> list[dict]:
    """输出规则清单，供文档与报告生成使用。"""
    return [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "level": r.level,
            "severity": r.severity,
            "basis": r.basis,
        }
        for r in RULES
    ]
