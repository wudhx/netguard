"""规则基类与通用工具。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models import Config, Finding


@dataclass(frozen=True)
class Rule:
    """一条校验规则的元数据 + 判定函数。

    level 语义：
      A —— 单设备配置即可确定性判定，结论可直接采信
      B —— 可给出提示，需结合运维意图人工确认
      C —— 需要多设备拓扑信息，本版本仅作占位提示，不计入指标
    """

    id: str
    name: str
    category: str
    level: str
    severity: str
    basis: str
    check: Callable[[Config], list[Finding]]


def finding(
    rule: Rule,
    message: str,
    evidence: str = "",
    line_no: int = 0,
    severity: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        category=rule.category,
        level=rule.level,
        severity=severity or rule.severity,
        message=message,
        evidence=evidence,
        line_no=line_no,
    )


def is_physical_port(name: str) -> bool:
    """是否为物理端口（区别于 Vlanif / LoopBack / NULL 等逻辑接口）。"""
    lower = name.lower()
    return not any(
        lower.startswith(prefix)
        for prefix in ("vlanif", "loopback", "null", "tunnel", "eth-trunk")
    )
