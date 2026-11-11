"""规则注册表。

新增规则：在对应模块里定义 Rule 实例并加入该模块的 RULES 列表即可，
引擎无需改动。
"""

from __future__ import annotations

from . import acl, interface, ospf, route, security, vlan
from .base import Rule

RULES: list[Rule] = (
    interface.RULES
    + ospf.RULES
    + acl.RULES
    + route.RULES
    + vlan.RULES
    + security.RULES
)

BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

__all__ = ["RULES", "BY_ID", "Rule"]
