"""规则引擎：把候选规则跑在配置上，收集 finding。

## 为什么需要独立一层

`core/rules/` 里每条规则都是纯函数，但没有「按什么顺序跑、跑哪些、
异常怎么办」的统一策略。CLI 需要它，agent 的工具层需要它，评测需要它。

三处各写一遍会立刻分叉：CLI 可能在某条规则抛异常时整体崩掉，
agent 的工具层可能静默吞掉异常，评测可能算出不同的结果。
把调度收敛到一处，才能保证「同一条规则在三个入口的判定完全一致」。

## 异常隔离

单条规则抛异常不得中断整轮巡检。理由：规则是人工写的，其中一条有 bug
是必然事件；若一条 bug 让整份报告消失，工具的可用性就等于最差那条规则。

隔离后必须在结果里**显式暴露**异常，而不是吞掉——吞掉会让「规则没报」
和「规则崩了」在报告里长得一模一样，后者是必须修的 bug，不能被掩盖。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Config, Finding, Role
from .profile import candidate_rules, infer_role
from .rules.base import RuleDef

__all__ = [
    "RuleOutcome",
    "RunResult",
    "run_rules",
    "run_all_rules",
]


@dataclass
class RuleOutcome:
    """一条规则的执行结果。成功与失败共用同一个类型，便于统一渲染。"""

    rule_id: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def hit_count(self) -> int:
        return len(self.findings)


@dataclass
class RunResult:
    """一次巡检的完整结果。"""

    device_id: str
    role: Role
    outcomes: list[RuleOutcome] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        return [f for o in self.outcomes for f in o.findings]

    @property
    def errors(self) -> dict[str, str]:
        return {o.rule_id: o.error for o in self.outcomes if o.error is not None}

    @property
    def rules_run(self) -> set[str]:
        return {o.rule_id for o in self.outcomes}

    def by_severity(self) -> dict[str, int]:
        """按严重度计数，供报告摘要区块使用。"""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        return counts


def run_rules(cfg: Config, rules: list[RuleDef]) -> list[RuleOutcome]:
    """在给定规则集上执行。每条独立隔离异常。"""
    outcomes: list[RuleOutcome] = []
    for rule in rules:
        try:
            outcomes.append(RuleOutcome(rule_id=rule.id, findings=list(rule.check(cfg))))
        except Exception as exc:  # noqa: BLE001 —— 隔离是刻意的
            outcomes.append(
                RuleOutcome(rule_id=rule.id, error=f"{type(exc).__name__}: {exc}")
            )
    return outcomes


def run_all_rules(cfg: Config, role: Role | None = None) -> RunResult:
    """按画像过滤候选规则后执行。

    这是 CLI 与 agent 工具层共同的唯一入口。两者若各自实现过滤，
    「同一份配置跑出不同结果」就是时间问题。
    """
    actual_role = role if role is not None else infer_role(cfg)
    candidates, skipped = candidate_rules(cfg, actual_role)
    return RunResult(
        device_id=cfg.device_id,
        role=actual_role,
        outcomes=run_rules(cfg, candidates),
        skipped=skipped,
    )
