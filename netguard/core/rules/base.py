"""规则基础设施：`@rule` 装饰器 + 自动注册表 + `finding()` 工厂。

## 扩展契约（架构 §5.7）

新增一条规则只允许三步：

1. 在对应类别文件写一个纯函数 `(cfg: Config) -> list[Finding]`
2. 给它加 `@rule(...)` 元数据
3. 在 `corpus/` 加正反样例，`expected/` 加期望结果

**除此之外不得改动任何文件**——注册表自动发现，故本模块不 import 具体规则模块，
而是在 `rules/__init__.py` 里统一导入触发注册。

## 为什么用装饰器而不是在列表里手写注册

手写列表时，「忘记把新规则加进 RULES」是一个静默失败：规则写了、测试过了、
但引擎永远不执行它，且没有任何报错。装饰器在导入期注册，配合 `__init__.py`
的模块导入，能保证「文件存在即生效」。
"""

from __future__ import annotations

from typing import Callable, Iterable

from ..models import Config, Finding, Nature, Needs, Role, RuleMeta, Severity

__all__ = [
    "rule",
    "RuleDef",
    "REGISTRY",
    "all_rules",
    "get_rule",
    "rules_for_role",
    "finding",
    "is_physical_port",
    "is_logical_interface",
]

RuleFunc = Callable[[Config], list[Finding]]


class RuleDef:
    """一条规则 = 元数据 + 判定函数。

    不可变：`meta` 是 frozen dataclass，`func` 创建后不再替换。
    """

    __slots__ = ("meta", "func")

    def __init__(self, meta: RuleMeta, func: RuleFunc) -> None:
        self.meta = meta
        self.func = func

    @property
    def id(self) -> str:
        return self.meta.id

    def check(self, cfg: Config) -> list[Finding]:
        return self.func(cfg)

    def __repr__(self) -> str:
        return f"<RuleDef {self.meta.id} {self.meta.title}>"


REGISTRY: dict[str, RuleDef] = {}


def rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    nature: Nature,
    category: str,
    needs: Needs,
    applies_to: Iterable[Role],
    doc_ref: str,
    known_fp: str = "",
    fp_mitigated: bool = False,
    examples: dict[str, str] | None = None,
) -> Callable[[RuleFunc], RuleFunc]:
    """把判定函数注册为一条规则。

    元数据约束（如 `known_fp` 非空时 severity 不得高于 LOW）由
    `RuleMeta.__post_init__` 强制，此处不重复校验。

    重复 ID 直接抛错：规则 ID 是报告、日志、评测的共同主键，
    撞 ID 会让「哪条规则报的」永久失准。
    """

    def decorator(func: RuleFunc) -> RuleFunc:
        if id in REGISTRY:
            raise ValueError(f"规则 ID 重复：{id}（已注册于 {REGISTRY[id]!r}）")

        meta = RuleMeta(
            id=id,
            title=title,
            severity=severity,
            nature=nature,
            category=category,
            needs=needs,
            applies_to=frozenset(applies_to),
            doc_ref=doc_ref,
            known_fp=known_fp,
            fp_mitigated=fp_mitigated,
            examples=examples or {},
        )
        REGISTRY[id] = RuleDef(meta, func)
        # 把元数据挂回函数，便于单测按函数名反查对应规则
        func.meta = meta  # type: ignore[attr-defined]
        return func

    return decorator


def all_rules() -> list[RuleDef]:
    """全部已注册规则，按 ID 排序以保证输出稳定。"""
    return [REGISTRY[k] for k in sorted(REGISTRY)]


def get_rule(rule_id: str) -> RuleDef | None:
    return REGISTRY.get(rule_id)


def rules_for_role(role: Role) -> list[RuleDef]:
    """按设备角色过滤候选规则（架构 §7.2）。

    `Role.UNKNOWN` 返回全量——兜底，宁可多查不可空转（架构 §7.3）。
    """
    return [r for r in all_rules() if r.meta.applies_to_role(role)]


def finding(
    meta: RuleMeta,
    *,
    location: str,
    message: str,
    evidence: str,
    line_no: int | None = None,
    hint: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    """构造一条 Finding。

    默认从元数据继承 severity / nature / basis，只在规则有正当理由
    降级时才显式传 severity（如 §5.6 的 VRF 场景降为 INFO）。

    `basis` 强制来自 `meta.doc_ref`——这是「事实层由规则生成、模型不参与」
    的具体落实：依据文案只允许写在规则元数据里，不散落在判定函数中。
    """
    return Finding(
        rule_id=meta.id,
        severity=severity or meta.severity,
        nature=meta.nature,
        location=location,
        message=message,
        evidence=evidence,
        basis=meta.doc_ref,
        line_no=line_no,
        hint=hint,
    )


_LOGICAL_PREFIXES = ("vlanif", "loopback", "null", "tunnel", "eth-trunk", "meth")


def is_logical_interface(name: str) -> bool:
    return name.lower().startswith(_LOGICAL_PREFIXES)


def is_physical_port(name: str) -> bool:
    """是否为物理端口（区别于 Vlanif / LoopBack / NULL 等逻辑接口）。"""
    return not is_logical_interface(name)
