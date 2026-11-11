"""OSPF 类规则：R05 — R10。"""

from __future__ import annotations

from ..models import Config, Finding
from ..netutil import ip_in_network, is_ipv4
from .base import Rule, finding


def _is_area0(area_id: str) -> bool:
    return area_id in ("0", "0.0.0.0")


def _r05(cfg: Config) -> list[Finding]:
    rule = R05
    out: list[Finding] = []
    for proc in cfg.ospf_processes.values():
        if not proc.areas:
            continue
        if not any(_is_area0(a) for a in proc.areas):
            out.append(
                finding(
                    rule,
                    f"OSPF 进程 {proc.pid} 未配置任何属于 Area 0 的接口，区域划分缺少骨干区域",
                    line_no=proc.line_no,
                )
            )
    return out


def _r06(cfg: Config) -> list[Finding]:
    rule = R06
    out: list[Finding] = []
    for proc in cfg.ospf_processes.values():
        seen: dict[tuple[str, str], list[str]] = {}
        for area_id, net, wild in proc.all_networks():
            seen.setdefault((net, wild), []).append(area_id)
        for (net, wild), areas in seen.items():
            if len(areas) > 1:
                out.append(
                    finding(
                        rule,
                        f"网段 {net} {wild} 被同时宣告进多个区域：{', '.join(sorted(areas))}",
                        line_no=proc.line_no,
                    )
                )
    return out


def _r07(cfg: Config) -> list[Finding]:
    rule = R07
    out: list[Finding] = []
    for proc in cfg.ospf_processes.values():
        if proc.router_id is None:
            out.append(
                finding(
                    rule,
                    f"OSPF 进程 {proc.pid} 未手工指定 Router-ID",
                    line_no=proc.line_no,
                )
            )
        elif proc.router_id == "0.0.0.0" or not is_ipv4(proc.router_id):
            out.append(
                finding(
                    rule,
                    f"OSPF 进程 {proc.pid} 的 Router-ID 非法：{proc.router_id}",
                    line_no=proc.line_no,
                )
            )
    return out


def _r08(cfg: Config) -> list[Finding]:
    rule = R08
    out: list[Finding] = []
    l3 = cfg.l3_interfaces()
    if not l3:
        return out
    for proc in cfg.ospf_processes.values():
        for area_id, net, wild in proc.all_networks():
            if not (is_ipv4(net) and is_ipv4(wild)):
                continue
            if not any(ip_in_network(i.ip or "", net, wild) for i in l3):
                out.append(
                    finding(
                        rule,
                        f"area {area_id} 宣告的网段 {net} {wild} 与本机任何接口网段均不匹配",
                        line_no=proc.areas[area_id].line_no if area_id in proc.areas else proc.line_no,
                    )
                )
    return out


def _r09(cfg: Config) -> list[Finding]:
    rule = R09
    out: list[Finding] = []
    passive = set()
    for proc in cfg.ospf_processes.values():
        passive.update(name.lower() for name in proc.passive_interfaces)
    for proc in cfg.ospf_processes.values():
        for area_id, net, wild in proc.all_networks():
            for iface in cfg.l3_interfaces():
                if not ip_in_network(iface.ip or "", net, wild):
                    continue
                if iface.link_type != "access":
                    continue
                if iface.name.lower() in passive:
                    continue
                out.append(
                    finding(
                        rule,
                        f"接入侧接口 {iface.name} 所在网段已宣告进 OSPF，但未配置 silent-interface",
                        line_no=iface.line_no,
                    )
                )
    return out


def _r10(cfg: Config) -> list[Finding]:
    """C 级：骨干区域连续性需要多设备拓扑，单设备配置只能提示。"""
    rule = R10
    out: list[Finding] = []
    for proc in cfg.ospf_processes.values():
        has_area0 = any(_is_area0(a) for a in proc.areas)
        if has_area0 and len(proc.areas) > 1:
            out.append(
                finding(
                    rule,
                    f"OSPF 进程 {proc.pid} 存在 Area 0 与多个非骨干区域，骨干区域连通性需拓扑信息校验",
                    line_no=proc.line_no,
                    severity="info",
                )
            )
    return out


R05 = Rule(
    id="R05",
    name="缺少 Area 0",
    category="OSPF",
    level="A",
    severity="high",
    basis="OSPF 骨干区域要求",
    check=_r05,
)

R06 = Rule(
    id="R06",
    name="同网段跨区域宣告",
    category="OSPF",
    level="A",
    severity="high",
    basis="OSPF 区域划分原则",
    check=_r06,
)

R07 = Rule(
    id="R07",
    name="Router-ID 非法",
    category="OSPF",
    level="A",
    severity="medium",
    basis="华为 VRP 配置指南",
    check=_r07,
)

R08 = Rule(
    id="R08",
    name="宣告网段无对应接口",
    category="OSPF",
    level="A",
    severity="medium",
    basis="OSPF 宣告有效性",
    check=_r08,
)

R09 = Rule(
    id="R09",
    name="接入侧未配 silent-interface",
    category="OSPF",
    level="B",
    severity="low",
    basis="OSPF 安全实践",
    check=_r09,
)

R10 = Rule(
    id="R10",
    name="Area 0 连续性",
    category="OSPF",
    level="C",
    severity="info",
    basis="OSPF 骨干区域连续性（需拓扑）",
    check=_r10,
)

RULES = [R05, R06, R07, R08, R09, R10]
