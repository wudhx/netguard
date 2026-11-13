"""OSPF 规则 OSPF-001 ~ OSPF-004。

四条均为 `Needs.SINGLE_DEVICE`：只看本机配置即可判定。
需要拓扑的（Area 0 连续性、跨设备邻居）一律不做，见 ROADMAP.md。
"""

from __future__ import annotations

from ..models import Config, Finding, Nature, Needs, Role, Severity
from .. import netutil
from .base import finding, rule

# 角色适用集按运维常识推导，非 §5.4 原文规定（§5.4 只列规则与严重度，
# 未规定 applies_to）。
# 排除接入层：接入交换机以二层转发为主，OSPF 通常由汇聚层代理终结。
# 即便个别接入交换机跑了 OSPF，也多为 `ospf enable` 单接口使能，
# 不涉及区域划分——区域的规划责任在汇聚与核心。
# 对这类设备报「区域覆盖不完整」是拿核心层的标准卡接入层，属噪声。
_OSPF_ROLES = (Role.CORE, Role.AGG, Role.BORDER)


def _norm(value: str) -> str:
    """区域号归一化：`0` 与 `0.0.0.0` 视为同一区域。

    VRP 两种写法等价，但字符串不等。不归一化会导致同一区域被当成两个，
    进而让 OSPF-001 产生大量误报。
    """
    text = value.strip()
    if "." in text:
        parts = text.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return str(int(parts[0]) << 24 | int(parts[1]) << 16 | int(parts[2]) << 8 | int(parts[3]))
        return text
    return str(int(text)) if text.isdigit() else text


def _declaring_areas(cfg: Config, iface_ip: str) -> dict[str, list[tuple[str, str]]]:
    """找出哪些区域宣告了覆盖该 IP 的网段。

    返回 {归一化区域号: [(network, wildcard), ...]}。
    """
    hits: dict[str, list[tuple[str, str]]] = {}
    for proc in cfg.ospf.values():
        for area_id, area in proc.areas.items():
            for net, wildcard in area.networks:
                if netutil.ip_in_network(iface_ip, net, wildcard):
                    hits.setdefault(_norm(area_id), []).append((net, wildcard))
    return hits


@rule(
    id="OSPF-001",
    title="同一接口 IP 被多个 Area 的 network 宣告",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="ospf",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_OSPF_ROLES,
    doc_ref="OSPF 区域划分原则：一个接口只能属于一个区域",
    known_fp="多 VRF 场景下不同 VRF 内可合法共存同网段；检测到 ip vpn-instance 时降为 INFO",
    fp_mitigated=True,
    examples={
        "positive": "corpus/case01_core_switch.txt",
        "negative": "corpus/case03_access_switch.txt",
    },
)
def same_ip_multi_area(cfg: Config) -> list[Finding]:
    """同一接口 IP 落入多个不同 Area 的 network 覆盖范围。

    这是区域划分的硬错误：同一接口会同时属于两个区域，导致 LSU 在区域间
    异常泛洪，且设备侧行为依实现而异（不是配置意图）。

    误报规避（§5.6 第 1 类）：出现 `ip vpn-instance` 时，不同 VRF 内
    同网段是合法的。解析器目前不区分 network 命令所属 VRF，因此无法
    精确判定，只能整体降为 INFO 并注明。
    """
    out: list[Finding] = []
    mitigated = cfg.has_vrf

    for iface in cfg.l3_interfaces():
        if not iface.ip:
            continue
        areas = _declaring_areas(cfg, iface.ip)
        if len(areas) < 2:
            continue

        area_list = "、".join(f"area {a}" for a in sorted(areas))
        evidence_parts = []
        for area_id in sorted(areas):
            for net, wildcard in areas[area_id]:
                evidence_parts.append(f"area {area_id}: network {net} {wildcard}")
        evidence = "；".join(evidence_parts)

        if mitigated:
            evidence += "（该配置含 ip vpn-instance，网段可能分属不同 VRF，仅供参考）"

        message = (
            f"接口 {iface.name}（{iface.ip}）被 {len(areas)} 个区域同时宣告：{area_list}"
        )
        if mitigated:
            # 降级理由必须进 message。报告正文读的是 message，读者看不到
            # INFO 的原因会以为规则误判了严重度。
            message += "［因配置含 VRF，暂降为提示］"

        out.append(
            finding(
                same_ip_multi_area.meta,
                location=f"interface {iface.name}",
                message=message,
                evidence=evidence,
                line_no=iface.line_no,
                hint="确认该网段应归属哪个区域，删除其余区域的 network 条目",
                severity=Severity.INFO if mitigated else None,
            )
        )

    return out


@rule(
    id="OSPF-002",
    title="network 宣告的网段内无任何本机接口",
    severity=Severity.MEDIUM,
    nature=Nature.DEFECT,
    category="ospf",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_OSPF_ROLES,
    doc_ref="OSPF 宣告有效性：network 只对命中的本机接口生效",
    known_fp="",
    examples={
        "positive": "corpus/case04_ospf_errors.txt",
        "negative": "corpus/case01_core_switch.txt",
    },
)
def network_without_interface(cfg: Config) -> list[Finding]:
    """network 命令宣告的网段内，本机没有任何接口。

    VRP 的 `network A W` 只对「IP 落在 A/W 范围内」的本机接口生效。
    若一个接口都没有命中，这条 network 命令是无效配置——通常是从
    其他设备复制配置时漏改网段。
    """
    out: list[Finding] = []

    ifaces = cfg.l3_interfaces()

    for proc in cfg.ospf.values():
        for area_id, area in proc.areas.items():
            for net, wildcard in area.networks:
                if not (netutil.is_ipv4(net) and netutil.is_valid_wildcard(wildcard)):
                    # 非法地址交由 OSPF 的其他规则（或 ACL-002 类似逻辑）处理，
                    # 本规则不对非法输入下断言，避免同一问题报两次。
                    continue

                covered = [i for i in ifaces if i.ip and netutil.ip_in_network(i.ip, net, wildcard)]
                if covered:
                    continue

                out.append(
                    finding(
                        network_without_interface.meta,
                        location=f"ospf {proc.process_id} area {area_id}",
                        message=(
                            f"area {area_id} 宣告 network {net} {wildcard}，"
                            f"但本机无任何接口落在该范围内"
                        ),
                        evidence=f"network {net} {wildcard}",
                        hint="确认该网段是否属于本设备；若不属于，删除此条 network",
                    )
                )

    return out


@rule(
    id="OSPF-003",
    title="OSPF 进程缺失 / router-id 未配或非法",
    severity=Severity.MEDIUM,
    nature=Nature.DEFECT,
    category="ospf",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_OSPF_ROLES,
    doc_ref="华为 VRP 配置指南：router-id 缺失时设备会用接口地址推导，可能导致邻居震荡",
    known_fp="",
    examples={
        "positive": "corpus/case04_ospf_errors.txt",
        "negative": "corpus/case02_border_router.txt",
    },
)
def router_id_invalid(cfg: Config) -> list[Finding]:
    """检查每个 OSPF 进程的 router-id。

    三种情形都算缺陷：
    1. 配了 area 却没有 ospf 进程（解析层面不会出现，属防御）
    2. router-id 未配置
    3. router-id 不是合法 IPv4，或是 0.0.0.0 / 组播等非法取值
    """
    out: list[Finding] = []

    _INVALID_VALUES = {"0.0.0.0", "255.255.255.255"}

    for pid, proc in sorted(cfg.ospf.items()):
        rid = proc.router_id

        if pid == 1 and not cfg.ospf:
            continue  # 不会发生，保留结构对称

        if rid is None:
            out.append(
                finding(
                    router_id_invalid.meta,
                    location=f"ospf {pid}",
                    message=f"OSPF 进程 {pid} 未显式配置 router-id",
                    evidence=f"ospf {pid}",
                    hint="为该进程配置稳定的 router-id（建议用 LoopBack 地址）",
                )
            )
            continue

        if not netutil.is_ipv4(rid):
            out.append(
                finding(
                    router_id_invalid.meta,
                    location=f"ospf {pid}",
                    message=f"OSPF 进程 {pid} 的 router-id `{rid}` 不是合法 IPv4 地址",
                    evidence=f"router-id {rid}",
                    hint="改为合法的点分十进制地址",
                )
            )
            continue

        if rid in _INVALID_VALUES:
            out.append(
                finding(
                    router_id_invalid.meta,
                    location=f"ospf {pid}",
                    message=f"OSPF 进程 {pid} 的 router-id `{rid}` 是保留值，不能用于标识设备",
                    evidence=f"router-id {rid}",
                    hint="改用该设备上某个稳定的接口地址",
                )
            )

    return out


@rule(
    id="OSPF-004",
    title="接口参与 OSPF 但未被任何 network 覆盖",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="ospf",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_OSPF_ROLES,
    doc_ref="OSPF 宣告完整性：ospf enable 的接口若未被 network 覆盖，不会进入该区域",
    known_fp="",
    examples={
        "positive": "corpus/case04_ospf_errors.txt",
        "negative": "corpus/case01_core_switch.txt",
    },
)
def interface_not_covered(cfg: Config) -> list[Finding]:
    """接口显式 `ospf enable N area X`，但该区域的 network 未覆盖其 IP。

    典型成因：先配了接口 enable，后来改了 IP 网段却忘了同步 network 命令。
    后果是接口静默地不进 OSPF——没有报错，邻居就是起不来。
    """
    out: list[Finding] = []

    for iface in cfg.interfaces.values():
        if iface.ospf_area is None or iface.ospf_process is None:
            continue
        if not iface.ip:
            # 没有 IP 却被 enable，属配置残留，用 OSPF-004 报不合适
            # （IF-002 会覆盖「三层接口未配 IP」的情形），此处跳过。
            continue

        proc = cfg.ospf.get(iface.ospf_process)
        if proc is None:
            out.append(
                finding(
                    interface_not_covered.meta,
                    location=f"interface {iface.name}",
                    message=(
                        f"接口 {iface.name} 配置了 ospf enable {iface.ospf_process}，"
                        f"但该 OSPF 进程不存在"
                    ),
                    evidence=f"ospf enable {iface.ospf_process} area {iface.ospf_area}",
                    line_no=iface.line_no,
                    hint=f"创建 ospf {iface.ospf_process} 进程，或删除接口上的 enable 命令",
                )
            )
            continue

        target_area = _norm(iface.ospf_area)
        area = None
        for area_id, candidate in proc.areas.items():
            if _norm(area_id) == target_area:
                area = candidate
                break

        if area is None:
            out.append(
                finding(
                    interface_not_covered.meta,
                    location=f"interface {iface.name}",
                    message=(
                        f"接口 {iface.name} 使能了 area {iface.ospf_area}，"
                        f"但进程 {iface.ospf_process} 下不存在该区域"
                    ),
                    evidence=f"ospf enable {iface.ospf_process} area {iface.ospf_area}",
                    line_no=iface.line_no,
                    hint=f"在 ospf {iface.ospf_process} 下创建 area {iface.ospf_area}",
                )
            )
            continue

        covered = any(
            netutil.ip_in_network(iface.ip, net, wildcard)
            for net, wildcard in area.networks
            if netutil.is_ipv4(net) and netutil.is_valid_wildcard(wildcard)
        )
        if covered:
            continue

        out.append(
            finding(
                interface_not_covered.meta,
                location=f"interface {iface.name}",
                message=(
                    f"接口 {iface.name}（{iface.ip}）已使能 area {iface.ospf_area}，"
                    f"但该区域没有任何 network 覆盖此地址"
                ),
                evidence=f"ospf enable {iface.ospf_process} area {iface.ospf_area}；ip {iface.ip}",
                line_no=iface.line_no,
                hint=f"在 area {target_area} 下增加对应的 network 命令",
            )
        )

    return out
