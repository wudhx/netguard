"""静态路由类规则：R15 — R17。"""

from __future__ import annotations

from ..models import Config, Finding
from ..netutil import is_contiguous_mask, is_ipv4, same_subnet
from .base import Rule, finding


def _is_default(route) -> bool:
    return route.dest == "0.0.0.0" and route.mask == "0.0.0.0"


def _r15(cfg: Config) -> list[Finding]:
    rule = R15
    out: list[Finding] = []
    l3 = cfg.l3_interfaces()
    if not l3:
        return out
    for route in cfg.static_routes:
        if not route.nexthop or not is_ipv4(route.nexthop):
            continue
        reachable = any(
            same_subnet(route.nexthop, i.mask, i.ip, i.mask)
            for i in l3
            if is_ipv4(i.ip or "") and is_contiguous_mask(i.mask or "")
        )
        if not reachable:
            out.append(
                finding(
                    rule,
                    f"静态路由 {route.dest}/{route.mask} 的下一跳 {route.nexthop} 不在任何直连网段内",
                    line_no=route.line_no,
                )
            )
    return out


def _r16(cfg: Config) -> list[Finding]:
    rule = R16
    out: list[Finding] = []
    for route in cfg.static_routes:
        if route.interface and route.nexthop is None:
            lower = route.interface.lower()
            if lower.startswith(("gigabitethernet", "ethernet", "xgigabitethernet", "40ge", "100ge")):
                out.append(
                    finding(
                        rule,
                        f"静态路由 {route.dest}/{route.mask} 仅指定以太网出接口 {route.interface} 而未指定下一跳",
                        line_no=route.line_no,
                    )
                )
    return out


def _r17(cfg: Config) -> list[Finding]:
    rule = R17
    out: list[Finding] = []
    defaults = [r for r in cfg.static_routes if _is_default(r)]
    if len(defaults) < 2:
        return out
    buckets: dict[int, list] = {}
    for route in defaults:
        buckets.setdefault(route.preference if route.preference is not None else 60, []).append(route)
    for pref, group in buckets.items():
        if len(group) > 1:
            hops = ", ".join(r.nexthop or r.interface or "?" for r in group)
            out.append(
                finding(
                    rule,
                    f"存在 {len(group)} 条优先级同为 {pref} 的默认路由（{hops}），未做优先级或浮动区分",
                    line_no=group[0].line_no,
                )
            )
    return out


R15 = Rule(
    id="R15",
    name="下一跳不可达",
    category="静态路由",
    level="A",
    severity="high",
    basis="路由可达性要求",
    check=_r15,
)

R16 = Rule(
    id="R16",
    name="以太网出接口未指定下一跳",
    category="静态路由",
    level="A",
    severity="high",
    basis="华为 VRP 语法要求",
    check=_r16,
)

R17 = Rule(
    id="R17",
    name="等价默认路由冗余",
    category="静态路由",
    level="B",
    severity="low",
    basis="路由冗余设计",
    check=_r17,
)

RULES = [R15, R16, R17]
