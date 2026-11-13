"""规则包入口。

**导入本包即完成全部规则注册。** 各规则模块在导入时通过 `@rule` 装饰器
写入 `base.REGISTRY`，因此这里必须显式 import 每个模块——漏一个，
该模块的规则就永远不会被发现，且不会有任何报错。

新增规则时只需在本文件加一行 import（这是扩展契约里唯一允许改动的
集中式文件；架构 §5.7 说的「不得改动任何文件」指规则本身之外不散落改动，
集中注册入口是必要的例外，否则无法自动发现）。
"""

from __future__ import annotations

from .base import (
    REGISTRY,
    RuleDef,
    all_rules,
    finding,
    get_rule,
    rule,
    rules_for_role,
)

# 导入即注册。顺序不重要（all_rules 按 ID 排序），但保持类别分组的可读性。
from . import acl, iface, ospf, route, security  # noqa: E402,F401

__all__ = [
    "REGISTRY",
    "RuleDef",
    "all_rules",
    "get_rule",
    "rule",
    "rules_for_role",
    "finding",
]
