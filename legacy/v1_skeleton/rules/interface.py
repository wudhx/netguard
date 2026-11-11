"""接口类规则：R01 — R04。"""

from __future__ import annotations

from ..models import Config, Finding
from ..netutil import is_contiguous_mask, is_ipv4, same_subnet
from .base import Rule, finding, is_physical_port


def _r01(cfg: Config) -> list[Finding]:
    rule = R01
    out: list[Finding] = []
    for iface in cfg.l3_interfaces():
        if not is_ipv4(iface.ip or ""):
            out.append(
                finding(rule, f"接口 {iface.name} 的 IP 地址格式非法：{iface.ip}", line_no=iface.line_no)
            )
            continue
        if not is_ipv4(iface.mask or "") or not is_contiguous_mask(iface.mask or ""):
            out.append(
                finding(
                    rule,
                    f"接口 {iface.name} 的子网掩码非法（非连续掩码）：{iface.mask}",
                    line_no=iface.line_no,
                )
            )
            continue
        if iface.mask in ("0.0.0.0", "255.255.255.255"):
            out.append(
                finding(
                    rule,
                    f"接口 {iface.name} 的掩码 {iface.mask} 不构成有效网段",
                    line_no=iface.line_no,
                )
            )
    return out


def _r02(cfg: Config) -> list[Finding]:
    rule = R02
    out: list[Finding] = []
    ifaces = [i for i in cfg.l3_interfaces() if is_ipv4(i.ip or "") and is_contiguous_mask(i.mask or "")]
    for idx, a in enumerate(ifaces):
        for b in ifaces[idx + 1:]:
            if a.ip == b.ip:
                out.append(
                    finding(
                        rule,
                        f"接口 {a.name} 与 {b.name} 配置了完全相同的 IP {a.ip}",
                        line_no=a.line_no,
                    )
                )
            elif same_subnet(a.ip, a.mask, b.ip, b.mask):
                out.append(
                    finding(
                        rule,
                        f"接口 {a.name}({a.ip}/{a.mask}) 与 {b.name}({b.ip}/{b.mask}) 网段重叠",
                        line_no=b.line_no,
                    )
                )
    return out


def _r03(cfg: Config) -> list[Finding]:
    rule = R03
    out: list[Finding] = []
    for iface in cfg.interfaces.values():
        if not is_physical_port(iface.name):
            continue
        if not iface.description:
            out.append(
                finding(
                    rule,
                    f"物理接口 {iface.name} 未配置 description，无法从配置判断链路用途",
                    line_no=iface.line_no,
                )
            )
    return out


def _r04(cfg: Config) -> list[Finding]:
    rule = R04
    out: list[Finding] = []
    for iface in cfg.interfaces.values():
        if not iface.admin_down:
            continue
        if iface.has_ip or iface.link_type == "trunk":
            role = "三层接口" if iface.has_ip else "Trunk 上联口"
            out.append(
                finding(
                    rule,
                    f"{role} {iface.name} 处于 shutdown 状态，需确认是否为规划内停用",
                    line_no=iface.line_no,
                )
            )
    return out


R01 = Rule(
    id="R01",
    name="接口 IP 与掩码合法性",
    category="接口",
    level="A",
    severity="high",
    basis="TCP/IP 协议规范",
    check=_r01,
)

R02 = Rule(
    id="R02",
    name="同设备内接口网段重叠",
    category="接口",
    level="A",
    severity="high",
    basis="路由表唯一性要求",
    check=_r02,
)

R03 = Rule(
    id="R03",
    name="物理接口缺少描述",
    category="接口",
    level="B",
    severity="low",
    basis="运维规范",
    check=_r03,
)

R04 = Rule(
    id="R04",
    name="关键接口被关闭",
    category="接口",
    level="B",
    severity="medium",
    basis="交付基线",
    check=_r04,
)

RULES = [R01, R02, R03, R04]
