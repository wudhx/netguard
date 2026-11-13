"""路由规则 RT-001。

## 为什么只有一条

架构 §5.5 明确排除三条：

- 「下一跳是否真的可达」→ 需迭代路由与全设备路由表
- 「默认路由跨设备冗余」→ 需邻居设备配置
- 「默认路由与明细路由冲突」（RT-002）→ 需路由表选路语义，单设备判不准

RT-001 保留，但把判定范围**收窄**为「下一跳是否在本机直连网段内」。
这个收窄是刻意的：宽判定会变成误报源，窄判定虽然会漏掉
「经过多跳后不可达」的情形，但那本来就不属于单设备能回答的问题。
"""

from __future__ import annotations

from ..models import Config, Finding, Nature, Needs, Role, Severity
from .. import netutil
from .base import finding, rule

# 角色适用集按运维常识推导，非 §5.4 原文规定。
# 排除接入层：接入交换机不做路由决策，静态路由通常不在它身上配。
# 若个别接入设备确有静态路由，能力过滤（cfg.static_routes 非空）会让它
# 照常执行——角色过滤是粗筛，能力过滤才是准绳，两层叠加不会漏报。
_ROUTE_ROLES = (Role.CORE, Role.AGG, Role.BORDER)


@rule(
    id="RT-001",
    title="静态路由下一跳不在任何直连网段",
    severity=Severity.LOW,
    nature=Nature.DEFECT,
    category="route",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ROUTE_ROLES,
    doc_ref="路由可达性：下一跳需落在某个直连网段，或由另一条路由覆盖",
    known_fp="递归静态路由（下一跳由其他路由覆盖）是合法配置；本规则只判直连关系，因此定 LOW",
    fp_mitigated=False,
    examples={
        "positive": "corpus/case01_core_switch.txt",
        "negative": "corpus/case02_border_router.txt",
    },
)
def nexthop_not_direct(cfg: Config) -> list[Finding]:
    """静态路由的下一跳既不直连，也没有被其他静态路由覆盖。

    判定分两步：

    1. 下一跳是否落在某个三层接口的直连网段内 → 直连，正常
    2. 否则看是否被其他静态路由的目标网段覆盖 → 递归路由，也正常
    3. 两者都不满足 → 报 LOW

    第 2 步很关键。只判直连会把递归静态路由全报成问题，
    而递归路由是合法且常见的写法（尤其在只有默认路由的小型网络里）。
    """
    out: list[Finding] = []

    direct_nets = [
        (i.ip, i.mask) for i in cfg.l3_interfaces() if i.ip and i.mask
    ]

    # 已配置的静态路由目标网段（用于识别递归路由）
    static_targets = [
        (r.dest, r.mask)
        for r in cfg.static_routes
        if netutil.is_ipv4(r.dest) and netutil.is_ipv4(r.mask) and netutil.is_contiguous_mask(r.mask)
    ]

    for route in cfg.static_routes:
        if route.next_hop is None:
            # 只指出接口的路由（如 ip route-static X Y GE0/0/1）不适用本规则
            continue
        if not netutil.is_ipv4(route.next_hop):
            # 下一跳不是 IP（可能是接口名被误放到 next_hop），跳过
            continue

        # 步骤 1：直连判定
        is_direct = any(
            netutil.ip_in_network(route.next_hop, ip, netutil.wildcard_to_mask(mask))
            for ip, mask in direct_nets
        )
        if is_direct:
            continue

        # 步骤 2：递归判定
        is_recursive = any(
            netutil.ip_in_network(
                route.next_hop, dest, netutil.wildcard_to_mask(mask)
            )
            for dest, mask in static_targets
        )
        if is_recursive:
            continue

        out.append(
            finding(
                nexthop_not_direct.meta,
                location=f"ip route-static {route.dest} {route.mask}",
                message=(
                    f"静态路由 {route.dest}/{netutil.mask_to_prefix(route.mask)} 的下一跳 "
                    f"{route.next_hop} 不在任何直连网段，也未被其他静态路由覆盖"
                ),
                evidence=f"ip route-static {route.dest} {route.mask} {route.next_hop}",
                line_no=route.line_no,
                hint=f"确认 {route.next_hop} 是否可达，或补充覆盖它的路由",
            )
        )

    return out
