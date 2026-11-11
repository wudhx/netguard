"""VLAN 类规则：R18 — R19。"""

from __future__ import annotations

from ..models import Config, Finding
from .base import Rule, finding


def _r18(cfg: Config) -> list[Finding]:
    rule = R18
    out: list[Finding] = []
    for iface in cfg.interfaces.values():
        referenced: list[tuple[int, str]] = []
        if iface.access_vlan is not None:
            referenced.append((iface.access_vlan, "access 口默认 VLAN"))
        if iface.trunk_pvid is not None:
            referenced.append((iface.trunk_pvid, "Trunk PVID"))
        for vlan in iface.trunk_allow:
            if vlan == -1:
                continue
            referenced.append((vlan, "Trunk 允许列表"))
        for vlan, where in referenced:
            if vlan not in cfg.vlans:
                out.append(
                    finding(
                        rule,
                        f"接口 {iface.name} 的{where}引用了未创建的 VLAN {vlan}",
                        line_no=iface.line_no,
                    )
                )
    return out


def _r19(cfg: Config) -> list[Finding]:
    rule = R19
    out: list[Finding] = []
    for iface in cfg.interfaces.values():
        if iface.link_type != "trunk":
            continue
        if not iface.trunk_allow:
            out.append(
                finding(
                    rule,
                    f"Trunk 接口 {iface.name} 未配置允许通过的 VLAN 列表",
                    line_no=iface.line_no,
                    severity="high",
                )
            )
        if iface.trunk_pvid is None:
            out.append(
                finding(
                    rule,
                    f"Trunk 接口 {iface.name} 未显式配置 PVID，使用默认 VLAN 1",
                    line_no=iface.line_no,
                    severity="low",
                )
            )
    return out


R18 = Rule(
    id="R18",
    name="引用未创建的 VLAN",
    category="VLAN",
    level="A",
    severity="high",
    basis="VLAN 配置一致性",
    check=_r18,
)

R19 = Rule(
    id="R19",
    name="Trunk 配置不完整",
    category="VLAN",
    level="A",
    severity="high",
    basis="二层转发正确性",
    check=_r19,
)

RULES = [R18, R19]
