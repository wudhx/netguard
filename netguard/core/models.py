"""数据模型与四个枚举。

本模块是零依赖确定性层的一部分：不读文件、不打印、不访问网络。
所有类型均为 `dataclass` 或 `Enum`，可用 `dataclasses.asdict()` 直接序列化。

分层约束（架构 §3.1）：本模块属于 core，不得导入 tools / agent / report。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """告警严重度。

    数值同时作为排序键，大者优先。这样报告排序不需要额外的映射表。
    """

    BLOCKER = 4   # 会导致业务中断
    HIGH = 3      # 高概率故障
    MEDIUM = 2    # 隐患
    LOW = 1       # 规范性问题
    INFO = 0      # 提示（含已知误报场景）


class Nature(Enum):
    """结论强度。

    needs 只描述「判定需要什么输入」，表达不了「这算不算问题」，
    因此必须独立一维。只有 DEFECT 计入 Precision/Recall。
    """

    DEFECT = "defect"                  # 确定性缺陷，计入主指标
    RECOMMENDATION = "recommendation"  # 规范建议，单独统计


class Needs(Enum):
    """判定所需输入。Phase 1 只实现 SINGLE_DEVICE。"""

    SINGLE_DEVICE = "single"
    MULTI_DEVICE = "multi"
    TOPOLOGY = "topology"


class Role(Enum):
    """设备角色。判定条件见 core/profile.py。"""

    CORE = "core"
    AGG = "agg"
    ACCESS = "access"
    BORDER = "border"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RuleMeta:
    """规则元数据。

    与规则实现（判定函数）分离存放，以便 Agent 层在**不导入判定逻辑**
    的前提下获取规则清单——这是 §6.2 中 `list_rules` 工具的数据来源。

    frozen=True 保证元数据不可被运行期篡改。
    """

    id: str
    title: str
    severity: Severity
    nature: Nature
    category: str
    needs: Needs
    applies_to: frozenset[Role]
    doc_ref: str
    known_fp: str = ""
    examples: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # 硬约束：带已知误报说明的规则，严重度最高只能到 LOW（架构 §5.1）
        if self.known_fp and self.severity.value > Severity.LOW.value:
            raise ValueError(
                f"规则 {self.id} 声明了 known_fp，severity 最高只能为 LOW，"
                f"当前为 {self.severity.name}"
            )

    def applies_to_role(self, role: Role) -> bool:
        """该规则是否适用于给定设备角色。

        UNKNOWN 角色一律返回 True——宁可多查，不可空转（架构 §7.3 兜底）。
        """
        if role is Role.UNKNOWN:
            return True
        return role in self.applies_to

    def to_dict(self) -> dict:
        """供工具层序列化给模型看。枚举取 value，保持可读。"""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "nature": self.nature.value,
            "category": self.category,
            "needs": self.needs.value,
            "applies_to": sorted(r.value for r in self.applies_to),
            "doc_ref": self.doc_ref,
            "known_fp": self.known_fp,
        }


@dataclass
class Finding:
    """一条发现项。

    事实层字段（rule_id / severity / location / line_no / evidence / basis）
    全部由规则代码确定，模型不得参与；模型的发挥空间只在归因层
    （标题、原因、建议），且需经 verify_claims 校验。
    """

    rule_id: str
    severity: Severity
    nature: Nature
    location: str
    message: str
    evidence: str
    basis: str
    line_no: int | None = None
    hint: str | None = None

    def __post_init__(self) -> None:
        # 证据片段限长，防止整段配置被塞进报告
        if len(self.evidence) > 200:
            self.evidence = self.evidence[:200] + "…"

    @property
    def key(self) -> str:
        """去重键：规则 + 位置。注意 value 侧是列表，本键不唯一。"""
        return f"{self.rule_id}@{self.location}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "nature": self.nature.value,
            "location": self.location,
            "line_no": self.line_no,
            "message": self.message,
            "evidence": self.evidence,
            "basis": self.basis,
            "hint": self.hint,
        }


# ---------------------------------------------------------------------------
# 配置侧数据结构（解析器输出）
# ---------------------------------------------------------------------------


@dataclass
class Interface:
    name: str
    ip: str | None = None
    mask: str | None = None
    admin_up: bool = True
    description: str | None = None
    # 区域号在 VRP 中既可写 `0` 也可写 `0.0.0.0`，统一按原始字符串保留，
    # 归一化比较交给规则层（不要在这里悄悄改写，否则追溯原始配置会对不上）。
    ospf_area: str | None = None
    ospf_process: int | None = None
    acl_in: str | None = None
    acl_out: str | None = None
    link_type: str | None = None
    access_vlan: int | None = None
    trunk_allow: list[int] = field(default_factory=list)
    line_no: int | None = None

    @property
    def has_ip(self) -> bool:
        return bool(self.ip and self.mask)

    @property
    def is_l3(self) -> bool:
        return self.has_ip

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
            "mask": self.mask,
            "admin_up": self.admin_up,
            "description": self.description,
            "ospf_area": self.ospf_area,
            "ospf_process": self.ospf_process,
            "acl_in": self.acl_in,
            "acl_out": self.acl_out,
            "link_type": self.link_type,
            "access_vlan": self.access_vlan,
            "trunk_allow": list(self.trunk_allow),
            "line_no": self.line_no,
        }


@dataclass
class OspfArea:
    area_id: str
    networks: list[tuple[str, str]] = field(default_factory=list)
    silent_interfaces: list[str] = field(default_factory=list)


@dataclass
class OspfProcess:
    process_id: int
    router_id: str | None = None
    areas: dict[str, OspfArea] = field(default_factory=dict)


@dataclass
class AclRule:
    seq: int
    action: str
    protocol: str
    source: str | None = None
    source_wildcard: str | None = None
    destination: str | None = None
    destination_wildcard: str | None = None
    dst_port: str | None = None
    line_no: int | None = None

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "action": self.action,
            "protocol": self.protocol,
            "source": self.source,
            "source_wildcard": self.source_wildcard,
            "destination": self.destination,
            "destination_wildcard": self.destination_wildcard,
            "dst_port": self.dst_port,
            "line_no": self.line_no,
        }


@dataclass
class Acl:
    number: str
    rules: list[AclRule] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.rules

    def only_deny_any(self) -> bool:
        """是否仅含一条 deny any（引用即全阻断）。"""
        return len(self.rules) == 1 and self.rules[0].action == "deny" and self.rules[0].protocol in ("ip", "any")


@dataclass
class AclBinding:
    interface: str
    acl_number: str
    direction: str  # inbound / outbound


@dataclass
class StaticRoute:
    dest: str
    mask: str
    next_hop: str | None = None
    interface: str | None = None
    line_no: int | None = None

    def to_dict(self) -> dict:
        return {
            "dest": self.dest,
            "mask": self.mask,
            "next_hop": self.next_hop,
            "interface": self.interface,
            "line_no": self.line_no,
        }


@dataclass
class Config:
    """一台设备的解析结果。

    raw_lines 仅供规则回溯行号，不参与判定——避免规则悄悄依赖原始文本
    而绕开结构化数据（那会让解析器的契约失效）。
    """

    device_id: str
    hostname: str | None = None
    vendor: str = "huawei"
    version: str | None = None
    interfaces: dict[str, Interface] = field(default_factory=dict)
    ospf: dict[int, OspfProcess] = field(default_factory=dict)
    acls: dict[str, Acl] = field(default_factory=dict)
    static_routes: list[StaticRoute] = field(default_factory=list)
    acl_bindings: list[AclBinding] = field(default_factory=list)
    vlans: set[int] = field(default_factory=set)
    telnet_enabled: bool = False
    snmp_communities: list[str] = field(default_factory=list)
    has_vrf: bool = False
    raw_lines: list[str] = field(default_factory=list)

    def l3_interfaces(self) -> list[Interface]:
        """所有配了 IP 的三层接口。"""
        return [i for i in self.interfaces.values() if i.is_l3]

    def interface_by_name(self, name: str) -> Interface | None:
        return self.interfaces.get(name)

    def ospf_area_of_interface(self, iface_name: str) -> str | None:
        """接口所属 OSPF 区域。

        优先取接口自身记录的区域（parser 在处理 `interface` 视图下的
        `ospf enable area X` 时写入）。接口未显式声明则返回 None。
        """
        iface = self.interfaces.get(iface_name)
        if iface is not None and iface.ospf_area is not None:
            return iface.ospf_area
        return None

    def areas_declaring(self, iface: Interface) -> list[str]:
        """哪些 OSPF 区域的 network 命令覆盖了该接口的网段。

        用于 OSPF-001（同接口被多区域宣告）与 OSPF-004（接口参与 OSPF
        但未被任何 network 覆盖）。这里只做「谁覆盖了我」的事实收集，
        判定逻辑留给规则函数。
        """
        hits: list[str] = []
        if not iface.has_ip:
            return hits
        from . import netutil  # 局部导入避免循环依赖

        for proc in self.ospf.values():
            for area in proc.areas.values():
                for net, wildcard in area.networks:
                    if netutil.ip_in_network(iface.ip, net, wildcard):
                        hits.append(area.area_id)
                        break
        return hits

    def has_default_route(self) -> bool:
        return any(r.dest == "0.0.0.0" and r.mask == "0.0.0.0" for r in self.static_routes)

    def bound_acls(self) -> dict[str, list[AclBinding]]:
        """接口名 → 该接口上的 ACL 绑定列表。"""
        out: dict[str, list[AclBinding]] = {}
        for b in self.acl_bindings:
            out.setdefault(b.interface, []).append(b)
        return out
