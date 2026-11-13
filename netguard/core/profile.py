"""设备画像与 Role 判定（架构 §7.3）。

本模块只有两个职责，都很窄：

1. `infer_role()`  —— 从配置推断设备角色
2. `candidate_rules()` —— 按 Role **与运行能力**两道过滤，得出候选规则集

## 为什么候选过滤必须有两道

§7.2 原文是「按 Role + 运行能力过滤」，只做 Role 一道是不够的：

- **Role 过滤**解决「这台设备该不该查这类问题」。接入交换机不跑 OSPF 区域
  覆盖判定，硬查只会制造噪声。
- **能力过滤**解决「这台设备有没有可供判定的输入」。一条「ACL 未被引用」的
  规则，在整份配置里根本没有 ACL 时，跑了必然是零命中——零命中不是「查过了
  没问题」，是「没东西可查」。两者在报告里的含义完全不同。

只做 Role 时，12 条规则对任何角色都返回 12 条（本次实测就是如此），
§7.2 画的「18 → 12 → 5—9」三层漏斗只有前两层发生，第三层形同虚设。

## 为什么能力过滤是有代价的

能力过滤会跳过一些规则，而「跳过」意味着可能漏报。所以：

- 跳过的每一条都必须记理由，写进报告（§8.2 区块 5「Agent 决策轨迹」已要求）
- `Role.UNKNOWN` 时不做能力过滤——角色都没认出来，谈不上「这台设备不该查」
- 能力判据必须保守：只跳过「输入显然不存在」的，不跳「输入可能存在但我没解析到」的

第 3 条尤其重要。`cfg.ospf` 为空有两种可能：设备真不跑 OSPF，或解析器没解析到。
前者该跳过，后者该报错。当前实现无法区分这两者，因此**只在能力判据完全不依赖
解析完整性时才用它**（如「配置里没有任何 ACL 定义」——ACL 定义是解析器最稳定的
部分，漏解析的概率远低于 OSPF 嵌套块）。
"""

from __future__ import annotations

from .models import Config, Role
from .rules.base import RuleDef, all_rules

__all__ = [
    "infer_role",
    "candidate_rules",
    "skip_reason",
]


# ===========================================================================
# Role 判定
# ===========================================================================


def infer_role(cfg: Config) -> Role:
    """按 §7.3 的判定树推断设备角色。

    判定顺序即优先级，不要调整——越靠前的判据越有辨识度。
    边界路由的判据（默认路由 + WAN 侧 ACL）比「L3 接口数量」更能说明问题：
    一台 L3 接口很多的边界路由器，首先应该被认成 BORDER 而非 CORE。
    """
    l3_count = len(cfg.l3_interfaces())
    has_ospf = bool(cfg.ospf)
    has_default_route = any(
        r.dest == "0.0.0.0" and r.mask == "0.0.0.0" for r in cfg.static_routes
    )
    # WAN 侧接口：物理端口上绑了 ACL，说明是出口
    has_wan_acl = any(
        b.interface.startswith(("GE", "XGE", "Serial", "GigabitEthernet", "XGigabitEthernet"))
        for b in cfg.acl_bindings
    )

    if has_default_route and has_wan_acl:
        return Role.BORDER
    if l3_count >= 4 and has_ospf:
        return Role.CORE
    if 2 <= l3_count <= 3 and has_ospf:
        return Role.AGG
    if l3_count <= 1 or not has_ospf:
        return Role.ACCESS
    return Role.UNKNOWN


# ===========================================================================
# 能力过滤
# ===========================================================================


def _capability(cfg: Config, rule: RuleDef) -> str | None:
    """规则所需的输入是否存在。返回 None 表示存在，返回字符串表示缺失原因。

    判据一律「输入完全不存在才跳过」。宁可多跑一条零命中，不可漏跳一条
    本该报的——漏报比噪声难发现得多。
    """
    rid = rule.id

    # OSPF 类：没有任何 OSPF 进程，就没有区域、network、router-id 可查。
    if rid.startswith("OSPF-") and not cfg.ospf:
        return "配置中无 OSPF 进程"

    # ACL 类：没有任何 ACL 定义，就没有规则可查。
    # 注意 ACL-004 是「空 ACL 被引用」，它恰恰需要「ACL 存在但为空」，
    # 因此 cfg.acls 为空时它也无从判定，同样跳过。
    if rid.startswith("ACL-") and not cfg.acls:
        return "配置中无 ACL 定义"

    # IF-002 判「意图是三层口却没配 IP」。整份配置里一个三层接口都没有时，
    # 全设备都是纯二层，不存在「配错的三层口」。
    if rid == "IF-002" and not cfg.l3_interfaces() and not cfg.acls:
        return "配置中无三层接口，也无 ACL 绑定（不构成三层口意图）"

    # RT-001 判「静态路由下一跳不在直连网段」。没有静态路由就没有可判对象。
    if rid == "RT-001" and not cfg.static_routes:
        return "配置中无静态路由"

    # SEC-001 判「Telnet 开启且无限制」。Telnet 本来就没开，不存在这个风险。
    if rid == "SEC-001" and not cfg.telnet_enabled:
        return "Telnet 未启用"

    return None


def skip_reason(cfg: Config, rule: RuleDef, role: Role) -> str | None:
    """该规则对本设备是否应跳过。返回 None 表示应执行，否则返回跳过理由。

    两道过滤合在一处，便于调用方一次性拿到结论与理由。
    """
    if role is not Role.UNKNOWN and not rule.meta.applies_to_role(role):
        return f"与设备角色 {role.value} 无关"

    if role is Role.UNKNOWN:
        # 角色未识别时只做能力过滤，不做角色过滤——让「不知道是什么设备」
        # 退化成「按能力能查多少查多少」，而不是「什么都不查」。
        return _capability(cfg, rule)

    return _capability(cfg, rule)


def candidate_rules(
    cfg: Config, role: Role | None = None
) -> tuple[list[RuleDef], dict[str, str]]:
    """候选规则集与跳过理由。

    返回 `(候选规则, {rule_id: 跳过理由})`。

    ## 为什么要返回跳过理由而不是只返回候选

    §8.2 报告区块 5 要求写明「执行了哪些规则、跳过了哪些及原因」。
    「跳过了 OSPF-002 因为配置无 OSPF 进程」这句话本身就是报告价值的一部分：
    它告诉用户「这台设备没有 OSPF，所以 OSPF 类风险不适用」，而不是让人
    误以为「OSPF 查过了，没问题」。

    这也直接支撑 M1 的可评测性：跳过理由是人工标注与自动决策的比对依据。
    """
    actual_role = role if role is not None else infer_role(cfg)

    candidates: list[RuleDef] = []
    skipped: dict[str, str] = {}

    for rule in all_rules():
        reason = skip_reason(cfg, rule, actual_role)
        if reason is None:
            candidates.append(rule)
        else:
            skipped[rule.id] = reason

    return candidates, skipped
