"""接口规则 IF-001 ~ IF-002。

只判定单设备内可确定的事实：地址冲突、网段重叠、掩码非法。
电路带宽、链路聚合、光模块告警这类需要硬件状态的，不在范围内。
"""

from __future__ import annotations

from ..models import Config, Finding, Nature, Needs, Role, Severity
from .. import netutil
from .base import finding, rule

# 角色适用集按运维常识推导，非 §5.4 原文规定。
# IF-001（IP 冲突）适用于全部角色：任何配了三层地址的设备都可能冲突，
# 且该问题后果严重（一个接口直接不通），没有理由按角色屏蔽。
_ALL_ROLES = (Role.CORE, Role.AGG, Role.BORDER, Role.ACCESS)

# IF-002（三层口未配 IP）排除接入层。
# 接入交换机的物理口不配 IP 是二层端口的正常形态（配了反而是错），
# 判「该配没配」会把正常配置报成缺陷——这是典型的拿三层标准套二层设备。
_NOT_ACCESS = (Role.CORE, Role.AGG, Role.BORDER)


@rule(
    id="IF-001",
    title="同设备内接口 IP 冲突或网段重叠",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="interface",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ALL_ROLES,
    doc_ref="路由表唯一性：同一设备内两个接口不能拥有重叠的直连网段",
    known_fp="多 VRF 场景下不同 VRF 内可合法共存同网段；检测到 ip vpn-instance 时降为 INFO",
    fp_mitigated=True,
    examples={
        "positive": "corpus/case01_core_switch.txt",
        "negative": "corpus/case03_access_switch.txt",
    },
)
def ip_conflict(cfg: Config) -> list[Finding]:
    """同设备内接口地址冲突或网段重叠。

    两种情形分开报告，因为运维动作不同：
    - IP 完全相同 → 必是配置错误，一个接口永远不通
    - 网段重叠但 IP 不同 → 路由表会出现两条同网段的直连路由，选路依掩码长度，
      行为不直观，且其中一段的地址不可达
    """
    out: list[Finding] = []
    mitigated = cfg.has_vrf

    ifaces = [i for i in cfg.l3_interfaces() if i.ip and i.mask]

    # ---- 1. IP 完全相同 ----
    by_ip: dict[str, list] = {}
    for iface in ifaces:
        by_ip.setdefault(iface.ip, []).append(iface)

    for ip, group in sorted(by_ip.items()):
        if len(group) < 2:
            continue
        names = "、".join(i.name for i in group)
        evidence = f"ip address {ip}；涉及接口：{names}"
        if mitigated:
            evidence += "（配置含 ip vpn-instance，可能分属不同 VRF，仅供参考）"

        out.append(
            finding(
                ip_conflict.meta,
                location=f"interface {group[0].name}",
                message=f"{len(group)} 个接口配置了相同 IP {ip}：{names}",
                evidence=evidence,
                line_no=group[0].line_no,
                hint="为每个接口分配唯一地址；若属不同 VRF 请在报告中注明",
                severity=Severity.INFO if mitigated else None,
            )
        )

    # ---- 2. 网段重叠（IP 不同） ----
    for idx, a in enumerate(ifaces):
        for b in ifaces[idx + 1:]:
            if a.ip == b.ip:
                continue  # 已在上面报过
            if not netutil.subnets_overlap(a.ip, a.mask, b.ip, b.mask):
                continue

            # 消息里给运维看的必须是原配置写法（ip + 掩码），
            # 不能只给规范化后的网络地址——否则拿着报告回配置文件里找不到对应行。
            a_prefix = netutil.mask_to_prefix(a.mask)
            b_prefix = netutil.mask_to_prefix(b.mask)
            a_norm = netutil.cidr_of(a.ip, a.mask)
            b_norm = netutil.cidr_of(b.ip, b.mask)

            evidence = (
                f"{a.name}: ip address {a.ip} {a.mask}（即 {a_norm}）；"
                f"{b.name}: ip address {b.ip} {b.mask}（即 {b_norm}）"
            )
            if mitigated:
                evidence += "（配置含 ip vpn-instance，可能分属不同 VRF，仅供参考）"

            out.append(
                finding(
                    ip_conflict.meta,
                    location=f"interface {a.name}",
                    message=(
                        f"接口 {a.name}（{a.ip}/{a_prefix}）与 "
                        f"{b.name}（{b.ip}/{b_prefix}）网段重叠"
                    ),
                    evidence=evidence,
                    line_no=a.line_no,
                    hint="重新规划网段，确保每个三层接口处于不同子网",
                    severity=Severity.INFO if mitigated else None,
                )
            )

    return out


@rule(
    id="IF-002",
    title="三层接口未配 IP 或掩码非法",
    severity=Severity.MEDIUM,
    nature=Nature.DEFECT,
    category="interface",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_NOT_ACCESS,
    doc_ref="TCP/IP 规范：三层接口必须有合法地址与连续掩码才能转发",
    known_fp="",
    examples={
        "positive": "corpus/case06_interface_errors.txt",
        "negative": "corpus/case02_border_router.txt",
    },
)
def l3_interface_invalid(cfg: Config) -> list[Finding]:
    """判定「意图是三层口但地址不完整」的接口。

    「意图是三层」的判据只能是显式线索，不能靠推测：
    - 接口名是 Vlanif / LoopBack / Tunnel（逻辑三层口，必须有 IP）
    - 接口上有 `ospf enable`
    - 接口上绑定了 ACL（绑 ACL 却无地址，ACL 无从生效）

    普通物理口没配 IP 是合法的（二层接入口），不能报——这是最容易
    制造大量误报的地方。
    """
    out: list[Finding] = []

    for iface in sorted(cfg.interfaces.values(), key=lambda i: i.name):
        is_logical = iface.name.lower().startswith(("vlanif", "loopback", "tunnel", "meth"))
        has_ospf = iface.ospf_area is not None
        has_acl = bool(iface.acl_in or iface.acl_out)

        if not (is_logical or has_ospf or has_acl):
            continue

        # 情形 A：完全没有地址
        if not iface.has_ip:
            if iface.ip and not iface.mask:
                msg = f"接口 {iface.name} 配置了 IP {iface.ip} 但缺少掩码"
            elif iface.mask and not iface.ip:
                msg = f"接口 {iface.name} 配置了掩码 {iface.mask} 但缺少 IP"
            else:
                msg = f"三层接口 {iface.name} 未配置 IP 地址"
            out.append(
                finding(
                    l3_interface_invalid.meta,
                    location=f"interface {iface.name}",
                    message=msg,
                    evidence=f"interface {iface.name}（无完整 ip address 配置）",
                    line_no=iface.line_no,
                    hint="为该接口配置合法的 ip address，或确认它不应是三层口",
                )
            )
            continue

        # 情形 B：有地址但格式非法
        if not netutil.is_ipv4(iface.ip):
            out.append(
                finding(
                    l3_interface_invalid.meta,
                    location=f"interface {iface.name}",
                    message=f"接口 {iface.name} 的 IP `{iface.ip}` 不是合法 IPv4 地址",
                    evidence=f"ip address {iface.ip} {iface.mask}",
                    line_no=iface.line_no,
                    hint="改为合法的点分十进制地址",
                )
            )
            continue

        if not netutil.is_contiguous_mask(iface.mask):
            out.append(
                finding(
                    l3_interface_invalid.meta,
                    location=f"interface {iface.name}",
                    message=f"接口 {iface.name} 的掩码 `{iface.mask}` 不是连续掩码",
                    evidence=f"ip address {iface.ip} {iface.mask}",
                    line_no=iface.line_no,
                    hint="改为连续掩码（如 255.255.255.0）",
                )
            )
            continue

        # 情形 C：主机地址全是 0 或全是 1（网络地址/广播地址被配到接口上）
        prefix = netutil.mask_to_prefix(iface.mask)
        if prefix < 31:
            lo, hi = netutil.network_range(iface.ip, iface.mask)
            ip_int = netutil.ip_to_int(iface.ip)
            if ip_int == lo:
                out.append(
                    finding(
                        l3_interface_invalid.meta,
                        location=f"interface {iface.name}",
                        message=f"接口 {iface.name} 的地址 {iface.ip} 是该网段的网络地址",
                        evidence=f"ip address {iface.ip} {iface.mask}",
                        line_no=iface.line_no,
                        hint="改用该网段内的可用主机地址",
                    )
                )
            elif ip_int == hi:
                out.append(
                    finding(
                        l3_interface_invalid.meta,
                        location=f"interface {iface.name}",
                        message=f"接口 {iface.name} 的地址 {iface.ip} 是该网段的广播地址",
                        evidence=f"ip address {iface.ip} {iface.mask}",
                        line_no=iface.line_no,
                        hint="改用该网段内的可用主机地址",
                    )
                )

    return out
