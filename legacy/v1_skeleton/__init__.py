"""NetGuard — 华为设备配置合规巡检工具。

对外只暴露三层：解析、规则、报告。
"""

from __future__ import annotations

__version__ = "0.1.0"

from .engine import describe_rules, hit_rule_ids, run, summarize
from .models import Config, Finding
from .parser import parse, parse_file

__all__ = [
    "__version__",
    "Config",
    "Finding",
    "parse",
    "parse_file",
    "run",
    "summarize",
    "hit_rule_ids",
    "describe_rules",
]
