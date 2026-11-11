"""华为 VRP 配置文本解析器。

按行扫描 + 缩进层级维护上下文块，把非结构化配置转成 Config 数据模型。
不使用第三方解析库，正则只用于字段级提取。
"""

from __future__ import annotations

import re

from .models import (
    Acl,
    AclRule,
    Config,
    Interface,
    OspfArea,
    OspfProcess,
    StaticRoute,
)

_IFACE_RE = re.compile(r"^interface\s+(\S+)$", re.IGNORECASE)
_OSPF_RE = re.compile(r"^ospf\s+(\d+)(?:\s+router-id\s+(\S+))?$", re.IGNORECASE)
_AREA_RE = re.compile(r"^area\s+(\S+)$", re.IGNORECASE)
_ACL_NUM_RE = re.compile(r"^acl\s+number\s+(\d+)$", re.IGNORECASE)
_ACL_NAME_RE = re.compile(r"^acl\s+name\s+(\S+)$", re.IGNORECASE)
_RULE_RE = re.compile(r"^rule\s+(\d+)\s+(\S+)\s*(\S*)", re.IGNORECASE)
_NETWORK_RE = re.compile(r"^network\s+(\S+)\s+(\S+)$", re.IGNORECASE)
_VLAN_BATCH_RE = re.compile(r"^vlan\s+batch\s+(.+)$", re.IGNORECASE)
_VLAN_SINGLE_RE = re.compile(r"^vlan\s+(\d+)$", re.IGNORECASE)
_ROUTE_RE = re.compile(r"^ip\s+route-static\s+(.+)$", re.IGNORECASE)
_IP_RE = re.compile(r"^ip\s+address\s+(\S+)\s+(\S+)$", re.IGNORECASE)
_DESC_RE = re.compile(r"^description\s+(.+)$", re.IGNORECASE)
_LINKTYPE_RE = re.compile(r"^port\s+link-type\s+(\S+)$", re.IGNORECASE)
_TRUNK_ALLOW_RE = re.compile(r"^port\s+trunk\s+allow-pass\s+vlan\s+(.+)$", re.IGNORECASE)
_TRUNK_PVID_RE = re.compile(r"^port\s+trunk\s+pvid\s+vlan\s+(\d+)$", re.IGNORECASE)
_ACCESS_VLAN_RE = re.compile(r"^port\s+default\s+vlan\s+(\d+)$", re.IGNORECASE)
_TRAFFIC_FILTER_RE = re.compile(
    r"^traffic-filter\s+(inbound|outbound)\s+acl\s+(?:number\s+)?(\d+)$", re.IGNORECASE
)
_SNMP_RE = re.compile(r"^snmp-agent\s+community\s+(?:read|write)\s+(\S+)", re.IGNORECASE)
_SILENT_RE = re.compile(r"^(?:silent-interface|passive-interface)\s+(\S+)$", re.IGNORECASE)


def _expand_vlan_list(text: str) -> list[int]:
    """展开 '10 20 30 to 35' 形式的 VLAN 列表。"""
    out: list[int] = []
    tokens = text.split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.lower() == "to" and out and i + 1 < len(tokens):
            start = out[-1]
            try:
                end = int(tokens[i + 1])
            except ValueError:
                i += 1
                continue
            out.extend(range(start + 1, end + 1))
            i += 2
            continue
        try:
            out.append(int(token))
        except ValueError:
            pass
        i += 1
    return out


def _parse_acl_rule(seq: int, action: str, protocol: str, rest: str, line_no: int) -> AclRule:
    rule = AclRule(seq=seq, line_no=line_no, action=action.lower(), protocol=(protocol or "ip").lower())
    tokens = rest.split()
    i = 0
    while i < len(tokens):
        key = tokens[i].lower()
        if key == "source" and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.lower() == "any":
                rule.src = "any"
                i += 2
                continue
            if i + 2 < len(tokens):
                rule.src = nxt
                rule.src_wild = tokens[i + 2]
                i += 3
                continue
        if key == "destination" and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.lower() == "any":
                rule.dst = "any"
                i += 2
                continue
            if i + 2 < len(tokens):
                rule.dst = nxt
                rule.dst_wild = tokens[i + 2]
                i += 3
                continue
        i += 1
    return rule


def _parse_static_route(args: str, line_no: int) -> StaticRoute | None:
    tokens = args.split()
    if len(tokens) < 3:
        return None
    dest, mask = tokens[0], tokens[1]
    route = StaticRoute(dest=dest, mask=mask, line_no=line_no)
    rest = tokens[2:]
    idx = 0
    while idx < len(rest):
        token = rest[idx]
        lower = token.lower()
        if lower == "preference" and idx + 1 < len(rest):
            try:
                route.preference = int(rest[idx + 1])
            except ValueError:
                pass
            idx += 2
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
            if route.nexthop is None:
                route.nexthop = token
        elif lower not in {"vpn-instance", "description", "tag"} and route.interface is None:
            route.interface = token
        idx += 1
    return route


def parse(text: str) -> Config:
    """把华为 VRP 配置文本解析为 Config。"""
    cfg = Config()
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cfg.raw_lines = lines

    block: str | None = None
    cur_iface: Interface | None = None
    cur_ospf: OspfProcess | None = None
    cur_area: OspfArea | None = None
    cur_acl: Acl | None = None
    in_vty = False

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "#":
            block = None
            cur_iface = cur_ospf = cur_area = cur_acl = None
            in_vty = False
            continue
        if stripped.startswith("!") and not stripped.startswith("!#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        lower = stripped.lower()
        negated = lower.startswith("undo ")

        # ---- 顶层命令（缩进 0）----
        if indent == 0:
            block = None
            cur_iface = cur_ospf = cur_area = cur_acl = None
            in_vty = False

            m = _IFACE_RE.match(stripped)
            if m:
                name = m.group(1)
                cur_iface = cfg.interfaces.get(name) or Interface(name=name, line_no=idx)
                cur_iface.line_no = cur_iface.line_no or idx
                cfg.interfaces[name] = cur_iface
                block = "interface"
                continue

            m = _OSPF_RE.match(stripped)
            if m:
                pid, rid = m.group(1), m.group(2)
                cur_ospf = cfg.ospf_processes.get(pid) or OspfProcess(pid=pid, line_no=idx)
                if rid:
                    cur_ospf.router_id = rid
                cfg.ospf_processes[pid] = cur_ospf
                block = "ospf"
                continue

            m = _ACL_NUM_RE.match(stripped) or _ACL_NAME_RE.match(stripped)
            if m:
                number = m.group(1)
                cur_acl = cfg.acls.get(number) or Acl(number=number, line_no=idx)
                cfg.acls[number] = cur_acl
                block = "acl"
                continue

            m = _VLAN_BATCH_RE.match(stripped)
            if m:
                cfg.vlans.update(_expand_vlan_list(m.group(1)))
                continue

            m = _VLAN_SINGLE_RE.match(stripped)
            if m:
                cfg.vlans.add(int(m.group(1)))
                continue

            m = _ROUTE_RE.match(stripped)
            if m:
                route = _parse_static_route(m.group(1), idx)
                if route:
                    cfg.static_routes.append(route)
                continue

            if lower.startswith("sysname"):
                cfg.sysname = stripped.split(maxsplit=1)[1] if " " in stripped else ""
                continue

            if lower == "stelnet server enable":
                cfg.ssh_enabled = True
                continue
            if lower == "undo stelnet server enable":
                cfg.ssh_enabled = False
                continue
            if lower == "telnet server enable":
                cfg.telnet_enabled = True
                continue
            if lower == "undo telnet server enable":
                cfg.telnet_enabled = False
                continue

            m = _SNMP_RE.match(stripped)
            if m:
                cfg.snmp_communities.append(m.group(1))
                continue

            if lower.startswith("user-interface"):
                in_vty = "vty" in lower
                block = "user-interface"
                continue

            continue

        # ---- 块内命令 ----
        if block == "interface" and cur_iface is not None:
            m = _IP_RE.match(stripped)
            if m:
                if negated:
                    cur_iface.ip = cur_iface.mask = None
                else:
                    cur_iface.ip, cur_iface.mask = m.group(1), m.group(2)
                continue
            m = _DESC_RE.match(stripped)
            if m:
                cur_iface.description = None if negated else m.group(1).strip()
                continue
            m = _LINKTYPE_RE.match(stripped)
            if m:
                cur_iface.link_type = None if negated else m.group(1).lower()
                continue
            m = _TRUNK_ALLOW_RE.match(stripped)
            if m:
                if negated:
                    cur_iface.trunk_allow = []
                else:
                    arg = m.group(1).strip()
                    if arg.lower() == "all":
                        cur_iface.trunk_allow = [-1]
                    else:
                        cur_iface.trunk_allow = _expand_vlan_list(arg)
                continue
            m = _TRUNK_PVID_RE.match(stripped)
            if m:
                cur_iface.trunk_pvid = None if negated else int(m.group(1))
                continue
            m = _ACCESS_VLAN_RE.match(stripped)
            if m:
                cur_iface.access_vlan = None if negated else int(m.group(1))
                continue
            m = _TRAFFIC_FILTER_RE.match(stripped)
            if m:
                if not negated:
                    cur_iface.traffic_filters.append((m.group(2), m.group(1).lower()))
                continue
            if lower == "shutdown":
                cur_iface.admin_down = True
                continue
            if lower == "undo shutdown":
                cur_iface.admin_down = False
                continue
            continue

        if block == "ospf" and cur_ospf is not None:
            m = _AREA_RE.match(stripped)
            if m:
                area_id = m.group(1)
                cur_area = cur_ospf.areas.get(area_id) or OspfArea(area_id=area_id, line_no=idx)
                cur_ospf.areas[area_id] = cur_area
                block = "ospf-area"
                continue
            m = _SILENT_RE.match(stripped)
            if m:
                if not negated:
                    cur_ospf.passive_interfaces.append(m.group(1))
                continue
            if lower.startswith("router-id"):
                parts = stripped.split()
                if len(parts) >= 2:
                    cur_ospf.router_id = parts[1]
                continue
            continue

        if block == "ospf-area" and cur_area is not None:
            m = _NETWORK_RE.match(stripped)
            if m:
                if not negated:
                    cur_area.networks.append((m.group(1), m.group(2)))
                continue
            # 回到 ospf 层的兄弟命令
            m = _AREA_RE.match(stripped)
            if m and cur_ospf is not None:
                area_id = m.group(1)
                cur_area = cur_ospf.areas.get(area_id) or OspfArea(area_id=area_id, line_no=idx)
                cur_ospf.areas[area_id] = cur_area
                continue
            continue

        if block == "acl" and cur_acl is not None:
            m = _RULE_RE.match(stripped)
            if m:
                if negated:
                    seq = int(m.group(1))
                    cur_acl.rules = [r for r in cur_acl.rules if r.seq != seq]
                else:
                    seq = int(m.group(1))
                    action = m.group(2)
                    protocol = m.group(3) or "ip"
                    rest = stripped[m.end():].strip()
                    if rest.lower().startswith(protocol.lower()):
                        rest = rest[len(protocol):].strip()
                    cur_acl.rules.append(_parse_acl_rule(seq, action, protocol, rest, idx))
                continue
            continue

        if block == "user-interface" and in_vty:
            if lower.startswith("protocol inbound"):
                if "ssh" in lower:
                    cfg.ssh_enabled = True
                if "telnet" in lower:
                    cfg.telnet_enabled = True
                continue
            continue

    return cfg


def parse_file(path: str) -> Config:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return parse(fh.read())
