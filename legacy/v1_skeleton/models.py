"""配置解析结果的数据模型。

全部使用 dataclass，保持不可变语义之外的最小必要可变性：
解析阶段填充，规则阶段只读。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Interface:
    """一个接口及其三层/二层配置。"""

    name: str
    line_no: int = 0
    description: str | None = None
    ip: str | None = None
    mask: str | None = None
    admin_down: bool = False
    link_type: str | None = None          # access / trunk / hybrid
    access_vlan: int | None = None
    trunk_allow: list[int] = field(default_factory=list)
    trunk_pvid: int | None = None
    traffic_filters: list[tuple[str, str]] = field(default_factory=list)  # (acl, direction)

    @property
    def has_ip(self) -> bool:
        return self.ip is not None and self.mask is not None

    @property
    def is_l3(self) -> bool:
        return self.has_ip


@dataclass
class OspfArea:
    area_id: str
    line_no: int = 0
    networks: list[tuple[str, str]] = field(default_factory=list)  # (network, wildcard)


@dataclass
class OspfProcess:
    pid: str
    line_no: int = 0
    router_id: str | None = None
    areas: dict[str, OspfArea] = field(default_factory=dict)
    passive_interfaces: list[str] = field(default_factory=list)

    def all_networks(self) -> list[tuple[str, str, str]]:
        """展开为 (area_id, network, wildcard) 列表。"""
        out: list[tuple[str, str, str]] = []
        for area in self.areas.values():
            for net, wild in area.networks:
                out.append((area.area_id, net, wild))
        return out


@dataclass
class AclRule:
    seq: int
    line_no: int = 0
    action: str = "permit"                # permit / deny
    protocol: str = "ip"
    src: str | None = None
    src_wild: str | None = None
    dst: str | None = None
    dst_wild: str | None = None


@dataclass
class Acl:
    number: str
    line_no: int = 0
    rules: list[AclRule] = field(default_factory=list)


@dataclass
class StaticRoute:
    dest: str
    mask: str
    line_no: int = 0
    nexthop: str | None = None
    interface: str | None = None
    preference: int | None = None


@dataclass
class Config:
    """单台设备的完整配置。"""

    sysname: str = ""
    interfaces: dict[str, Interface] = field(default_factory=dict)
    ospf_processes: dict[str, OspfProcess] = field(default_factory=dict)
    acls: dict[str, Acl] = field(default_factory=dict)
    static_routes: list[StaticRoute] = field(default_factory=list)
    vlans: set[int] = field(default_factory=set)
    telnet_enabled: bool = False
    ssh_enabled: bool = False
    snmp_communities: list[str] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)

    def l3_interfaces(self) -> list[Interface]:
        return [i for i in self.interfaces.values() if i.has_ip]

    def acl_applications(self) -> list[tuple[str, str, str]]:
        """展开为 (acl_number, interface, direction)。"""
        out: list[tuple[str, str, str]] = []
        for iface in self.interfaces.values():
            for acl, direction in iface.traffic_filters:
                out.append((acl, iface.name, direction))
        return out


@dataclass
class Finding:
    """一条被规则命中的风险。"""

    rule_id: str
    rule_name: str
    category: str
    level: str            # A / B / C
    severity: str         # high / medium / low
    message: str
    evidence: str = ""
    line_no: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "level": self.level,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "line_no": self.line_no,
        }
