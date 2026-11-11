"""华为 VRP 配置解析器。

把非结构化配置文本转成 `Config` 数据模型。纯函数：不读文件（`parse_file`
除外）、不打印、不访问网络、无全局状态。

## 为什么用「上下文栈」而不是单个 block 变量

VRP 是缩进敏感语言，同一个命令在不同缩进层级含义完全不同：

    interface GigabitEthernet0/0/1
     ip address 10.1.1.1 255.255.255.0     ← 接口地址
    ospf 1
     area 0.0.0.0
      network 10.1.1.0 0.0.0.255          ← OSPF 区域宣告

若只用一个 `block` 变量记录「当前块」，一旦遇到 `area` 内嵌在 `ospf` 内
这种二级嵌套，就得在块内再写特判回退逻辑，且极易串味。改用**栈**后，
每层缩进推进/退栈，语义与文本结构一一对应。

## undo 语义

`undo X` 不是「给 X 加个反向操作」那么简单，要分三种粒度：

1. **属性级**：`undo ip address` → 清空该接口的 ip/mask
2. **对象级**：`undo acl number 3000` → 删除整个 ACL
3. **开关级**：`undo shutdown` → 恢复 admin_up；`undo telnet server enable` → 关闭

本实现按命令形态分别处理，不做统一的「取反」抽象——因为三者撤销的
对象粒度不同，强行统一会写出难懂的代码。

## 设计取舍：宁可少解析，不要错解析

无法识别的行一律跳过，不猜测。理由：解析错误会直接变成规则的误报，
而漏解析只导致覆盖率下降——前者污染指标，后者只是少查。
"""

from __future__ import annotations

import re

from .models import (
    Acl,
    AclBinding,
    AclRule,
    Config,
    Interface,
    OspfArea,
    OspfProcess,
    StaticRoute,
)

# ---------------------------------------------------------------------------
# 正则：只做字段级提取，不做整段结构识别
# ---------------------------------------------------------------------------

_IFACE_RE = re.compile(r"^interface\s+(\S+)$", re.IGNORECASE)
_OSPF_RE = re.compile(r"^ospf\s+(\d+)(?:\s+router-id\s+(\S+))?$", re.IGNORECASE)
_ROUTER_ID_RE = re.compile(r"^router-id\s+(\S+)$", re.IGNORECASE)
_AREA_RE = re.compile(r"^area\s+(\S+)$", re.IGNORECASE)
_NETWORK_RE = re.compile(r"^network\s+(\S+)\s+(\S+)$", re.IGNORECASE)
_SILENT_RE = re.compile(r"^(?:silent-interface|passive-interface)\s+(\S+)$", re.IGNORECASE)

_ACL_HEAD_RE = re.compile(r"^acl\s+(?:number\s+)?(\d+)$", re.IGNORECASE)
_ACL_NAME_RE = re.compile(r"^acl\s+name\s+(\S+)$", re.IGNORECASE)
_RULE_RE = re.compile(r"^rule\s+(\d+)\s+(\S+)(?:\s+(.*))?$", re.IGNORECASE)
# 撤销整条 rule 时只给序号，不带 action，需单独匹配
_RULE_UNDO_RE = re.compile(r"^rule\s+(\d+)$", re.IGNORECASE)

_VLAN_BATCH_RE = re.compile(r"^vlan\s+batch\s+(.+)$", re.IGNORECASE)
_VLAN_SINGLE_RE = re.compile(r"^vlan\s+(\d+)$", re.IGNORECASE)

_ROUTE_RE = re.compile(r"^ip\s+route-static\s+(.+)$", re.IGNORECASE)
_IP_ADDR_RE = re.compile(r"^ip\s+address\s+(\S+)\s+(\S+)$", re.IGNORECASE)
_DESC_RE = re.compile(r"^description\s+(.+)$", re.IGNORECASE)
_LINK_TYPE_RE = re.compile(r"^port\s+link-type\s+(\S+)$", re.IGNORECASE)
_ACCESS_VLAN_RE = re.compile(r"^port\s+default\s+vlan\s+(\d+)$", re.IGNORECASE)
_TRUNK_ALLOW_RE = re.compile(r"^port\s+trunk\s+allow-pass\s+vlan\s+(.+)$", re.IGNORECASE)
_TRAFFIC_FILTER_RE = re.compile(
    r"^traffic-filter\s+(inbound|outbound)\s+acl\s+(?:number\s+)?(\S+)$", re.IGNORECASE
)
_OSPF_ENABLE_RE = re.compile(r"^ospf\s+enable\s+(\d+)\s+area\s+(\S+)$", re.IGNORECASE)

_SNMP_RE = re.compile(
    # community 名后可能跟 `cipher` / `simple` 加密标记，需跳过。
    # 例：`snmp-agent community read cipher %^%#abc%^%#`
    r"^snmp-agent\s+community\s+(?:read|write)\s+(?:cipher\s+|simple\s+)?(\S+)",
    re.IGNORECASE,
)
_SYSNAME_RE = re.compile(r"^sysname\s+(.+)$", re.IGNORECASE)
_VERSION_RE = re.compile(r"^version\s+(\S+)$", re.IGNORECASE)
_VRF_RE = re.compile(r"^ip\s+vpn-instance\s+(\S+)", re.IGNORECASE)

# IPv4 点分十进制（用于静态路由字段分类）
_IPV4_TEXT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# 静态路由里需要跳过的关键字（其后的值是参数，不是下一跳/出接口）
_ROUTE_SKIP_KEYS = {"preference", "tag", "description", "vpn-instance", "track", "bfd"}


def expand_vlan_list(text: str) -> list[int]:
    """展开 VLAN 列表表达式，返回去重且保序的整数列表。

    支持三种写法混排：
        "10"            → [10]
        "10 20 30"      → [10, 20, 30]
        "10 20 30 to 35"→ [10, 20, 30, ..., 35]

    逆序区间（`35 to 30`）也接受，按升序展开——设备侧这样配是合法的，
    解析器不应因其「看起来奇怪」就丢弃。
    """
    out: list[int] = []
    seen: set[int] = set()

    def _push(v: int) -> None:
        if v not in seen:
            seen.add(v)
            out.append(v)

    tokens = text.replace(",", " ").split()
    i = 0
    pending_start: int | None = None  # 等待 `to` 接续的数字

    while i < len(tokens):
        tok = tokens[i]

        if tok.lower() == "to":
            if pending_start is not None and i + 1 < len(tokens) and _is_int(tokens[i + 1]):
                end = int(tokens[i + 1])
                lo, hi = sorted((pending_start, end))
                # 先把区间起点从结果里撤回，保证整段按升序连续输出。
                # 例：`35 to 30` 应得 [30..35]，而不是 [35, 30..34]。
                if pending_start in seen:
                    seen.discard(pending_start)
                    out.remove(pending_start)
                for v in range(lo, hi + 1):
                    _push(v)
                pending_start = None
                i += 2
                continue
            # 孤立的 `to`（前无数字或后无数字）：跳过
            pending_start = None
            i += 1
            continue

        if _is_int(tok):
            value = int(tok)
            _push(value)
            pending_start = value
            i += 1
            continue

        pending_start = None
        i += 1

    return out


def _is_int(text: str) -> bool:
    try:
        int(text)
        return True
    except (TypeError, ValueError):
        return False


def _vlan_in_range(value: int) -> bool:
    """VRP 合法 VLAN 范围为 1—4094。"""
    return 1 <= value <= 4094


def _parse_acl_rule(seq: int, action: str, rest: str, line_no: int) -> AclRule:
    """解析一条 ACL rule。

    语法（简化）：
        rule <seq> <permit|deny> [<protocol>] [source <addr> <wild> | source any]
                                            [destination <addr> <wild> | destination any]
                                            [destination-port eq <port>]

    缺省协议为 ip；缺省地址为 any（即不写 source 表示任意源）。
    """
    tokens = rest.split() if rest else []
    protocol = "ip"
    idx = 0

    # 第一个 token 若不是关键字，就是协议名
    if tokens and tokens[0].lower() not in {
        "source", "destination", "destination-port", "source-port",
        "time-range", "fragment", "icmp-type", "vpn-instance",
    }:
        protocol = tokens[0].lower()
        idx = 1

    rule = AclRule(
        seq=seq,
        action=action.lower(),
        protocol=protocol,
        line_no=line_no,
    )

    while idx < len(tokens):
        key = tokens[idx].lower()

        if key in ("source", "destination"):
            value, consumed = _read_addr(tokens, idx + 1)
            if key == "source":
                rule.source, rule.source_wildcard = value
            else:
                rule.destination, rule.destination_wildcard = value
            idx += consumed
            continue

        if key == "destination-port" and idx + 2 < len(tokens):
            rule.dst_port = tokens[idx + 2]
            idx += 3
            continue

        idx += 1

    return rule


def _read_addr(tokens: list[str], idx: int) -> tuple[tuple[str | None, str | None], int]:
    """读取地址与其反掩码。

    返回 ((地址, 反掩码), 消费的 token 数)。`any` 视为无地址约束。
    地址后若没有合法的反掩码，则该地址视为非法，返回 (None, None) 消费 1 个，
    让上层继续扫描后续关键字——避免把一个错误的地址当成有效约束。
    """
    if idx >= len(tokens):
        return (None, None), 0
    if tokens[idx].lower() == "any":
        return (None, None), 1
    if idx + 1 < len(tokens) and tokens[idx + 1].lower() != "any":
        return (tokens[idx], tokens[idx + 1]), 2
    # 只有地址没有反掩码：按主机地址处理（反掩码 0.0.0.0）
    return (tokens[idx], "0.0.0.0"), 1


def _parse_static_route(args: str, line_no: int) -> StaticRoute | None:
    """解析 `ip route-static <dest> <mask> [next-hop | interface] ...`。"""
    tokens = args.split()
    if len(tokens) < 2:
        return None

    dest, mask = tokens[0], tokens[1]
    route = StaticRoute(dest=dest, mask=mask, line_no=line_no)

    idx = 2
    while idx < len(tokens):
        tok = tokens[idx]
        low = tok.lower()

        if low in _ROUTE_SKIP_KEYS:
            # 跳过该关键字及其参数
            idx += 2
            continue

        if _IPV4_TEXT_RE.match(tok):
            if route.next_hop is None:
                route.next_hop = tok
        elif route.interface is None:
            route.interface = tok
        idx += 1

    return route


class _Ctx:
    """解析上下文。

    用属性而非栈保存当前块，是因为 VRP 的块类型彼此互斥：
    一个 `#` 就结束整个块，不存在「接口内嵌 OSPF」这类结构。
    真正需要栈语义的是 **ospf → area** 两层，这里用 cur_ospf/cur_area
    两级指针表达，比通用栈更直观且不易出错。
    """

    __slots__ = (
        "block", "iface", "ospf", "area", "acl",
        "in_ospf_area", "in_vty", "in_vlan_view",
    )

    def __init__(self) -> None:
        self.block: str | None = None
        self.iface: Interface | None = None
        self.ospf: OspfProcess | None = None
        self.area: OspfArea | None = None
        self.acl: Acl | None = None
        self.in_ospf_area = False
        self.in_vty = False
        self.in_vlan_view = False

    def reset(self) -> None:
        """遇到 `#` 或顶层命令时清空块上下文。"""
        self.block = None
        self.iface = None
        self.ospf = None
        self.area = None
        self.acl = None
        self.in_ospf_area = False
        self.in_vty = False
        self.in_vlan_view = False


def parse(text: str, device_id: str = "unknown") -> Config:
    """把华为 VRP 配置文本解析为 `Config`。

    参数
    ----
    text:
        完整配置文本。CRLF / CR / LF 换行均可。
    device_id:
        设备标识。未提供时用 "unknown"，也可从 sysname 回填。

    返回
    ----
    填充完毕的 `Config`。无法识别的行被静默跳过。
    """
    cfg = Config(device_id=device_id)
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    cfg.raw_lines = lines

    ctx = _Ctx()

    for line_no, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if not line.strip():
            continue

        stripped = line.strip()

        # 分隔符：`#` 结束当前块；`!` 注释行直接跳过
        if stripped == "#":
            ctx.reset()
            continue
        if stripped.startswith("!"):
            continue

        indent = len(line) - len(line.lstrip(" \t"))
        lower = stripped.lower()
        negated = lower.startswith("undo ")
        # 去掉 undo 前缀后的有效命令体
        body = stripped[5:].strip() if negated else stripped
        body_lower = body.lower()

        # ---------------------------------------------------------------
        # 顶层（缩进 0）：块起始命令与全局配置
        # ---------------------------------------------------------------
        if indent == 0:
            ctx.reset()

            if _parse_top_level(cfg, ctx, body, body_lower, negated, line_no):
                continue
            continue

        # ---------------------------------------------------------------
        # 块内（缩进 > 0）
        # ---------------------------------------------------------------
        _parse_in_block(cfg, ctx, body, body_lower, negated, line_no)

    return cfg


def _parse_top_level(
    cfg: Config,
    ctx: _Ctx,
    body: str,
    body_lower: str,
    negated: bool,
    line_no: int,
) -> bool:
    """处理缩进为 0 的命令。返回 True 表示已识别。"""
    m = _IFACE_RE.match(body)
    if m:
        name = m.group(1)
        iface = cfg.interfaces.get(name)
        if iface is None:
            iface = Interface(name=name, line_no=line_no)
            cfg.interfaces[name] = iface
        ctx.block = "interface"
        ctx.iface = iface
        return True

    m = _OSPF_RE.match(body)
    if m:
        pid = int(m.group(1))
        if negated:
            cfg.ospf.pop(pid, None)
            return True
        proc = cfg.ospf.get(pid)
        if proc is None:
            proc = OspfProcess(process_id=pid)
            cfg.ospf[pid] = proc
        if m.group(2):
            proc.router_id = m.group(2)
        ctx.block = "ospf"
        ctx.ospf = proc
        return True

    m = _ACL_HEAD_RE.match(body) or _ACL_NAME_RE.match(body)
    if m:
        number = m.group(1)
        if negated:
            cfg.acls.pop(number, None)
            return True
        acl = cfg.acls.get(number)
        if acl is None:
            acl = Acl(number=number)
            cfg.acls[number] = acl
        ctx.block = "acl"
        ctx.acl = acl
        return True

    m = _VLAN_BATCH_RE.match(body)
    if m:
        for v in expand_vlan_list(m.group(1)):
            if _vlan_in_range(v):
                cfg.vlans.add(v)
        return True

    m = _VLAN_SINGLE_RE.match(body)
    if m:
        v = int(m.group(1))
        if _vlan_in_range(v):
            cfg.vlans.add(v)
        ctx.block = "vlan-view"
        ctx.in_vlan_view = True
        return True

    m = _ROUTE_RE.match(body)
    if m:
        if negated:
            target = _parse_static_route(m.group(1), line_no)
            if target is not None:
                cfg.static_routes = [
                    r for r in cfg.static_routes
                    if not (
                        r.dest == target.dest
                        and r.mask == target.mask
                        and r.next_hop == target.next_hop
                        and r.interface == target.interface
                    )
                ]
            return True
        route = _parse_static_route(m.group(1), line_no)
        if route is not None:
            cfg.static_routes.append(route)
        return True

    m = _SYSNAME_RE.match(body)
    if m:
        cfg.hostname = m.group(1).strip()
        if cfg.device_id == "unknown":
            cfg.device_id = cfg.hostname
        return True

    m = _VERSION_RE.match(body)
    if m:
        cfg.version = m.group(1)
        return True

    if _VRF_RE.match(body):
        cfg.has_vrf = True
        return True

    # ---- 开关类：必须区分正反，不能只看 startswith ----
    if body_lower in ("telnet server enable",):
        cfg.telnet_enabled = not negated
        return True
    if body_lower in ("stelnet server enable",):
        # 不影响 telnet_enabled，仅记录（SSH 不作为 Phase 1 规则输入）
        return True

    m = _SNMP_RE.match(body)
    if m:
        if not negated:
            cfg.snmp_communities.append(m.group(1))
        return True

    if body_lower.startswith("user-interface"):
        ctx.block = "user-interface"
        ctx.in_vty = "vty" in body_lower
        return True

    return False


def _parse_in_block(
    cfg: Config,
    ctx: _Ctx,
    body: str,
    body_lower: str,
    negated: bool,
    line_no: int,
) -> None:
    """处理缩进 > 0 的命令。"""
    block = ctx.block

    if block == "interface" and ctx.iface is not None:
        _parse_interface_body(cfg, ctx.iface, body, body_lower, negated, line_no)
        return

    if block == "ospf":
        _parse_ospf_body(cfg, ctx, body, body_lower, negated, line_no)
        return

    if block == "ospf-area":
        # area 视图内若再次出现 `area X`（同级新区域）或 `router-id`，
        # 说明已经回到 ospf 进程层，转交进程层处理——否则后续 network
        # 会被错误地塞进上一个区域。
        if _AREA_RE.match(body) or _ROUTER_ID_RE.match(body):
            _parse_ospf_body(cfg, ctx, body, body_lower, negated, line_no)
        else:
            _parse_ospf_area_body(cfg, ctx, body, body_lower, negated, line_no)
        return

    if block == "acl" and ctx.acl is not None:
        _parse_acl_body(ctx.acl, body, negated, line_no)
        return

    # user-interface / vlan-view 等暂无需提取结构化字段，静默跳过。


def _parse_interface_body(
    cfg: Config,
    iface: Interface,
    body: str,
    body_lower: str,
    negated: bool,
    line_no: int,
) -> None:
    # ---- 无参数撤销：必须按 body 的纯关键字形式匹配 ----
    # 这类命令 `undo X` 剥离前缀后只剩 `X`，与正向命令 `X <参数>` 形态不同，
    # 但会与「正向命令的省略写法」撞形，故先判 negated 再匹配。
    if negated:
        if body_lower == "ip address":
            iface.ip = None
            iface.mask = None
            return
        if body_lower == "description":
            iface.description = None
            return
        if body_lower.startswith("traffic-filter"):
            direction = "inbound" if "inbound" in body_lower else "outbound"
            if direction == "inbound":
                iface.acl_in = None
            else:
                iface.acl_out = None
            cfg.acl_bindings = [
                b for b in cfg.acl_bindings
                if not (b.interface == iface.name and b.direction == direction)
            ]
            return
        if body_lower == "shutdown":
            # `undo shutdown` 剥离后正好是 "shutdown"，语义是恢复开启
            iface.admin_up = True
            return

    m = _IP_ADDR_RE.match(body)
    if m:
        iface.ip = m.group(1)
        iface.mask = m.group(2)
        return

    m = _DESC_RE.match(body)
    if m:
        iface.description = m.group(1).strip()
        return

    m = _LINK_TYPE_RE.match(body)
    if m:
        iface.link_type = None if negated else m.group(1).lower()
        return

    m = _ACCESS_VLAN_RE.match(body)
    if m:
        iface.access_vlan = None if negated else int(m.group(1))
        return

    m = _TRUNK_ALLOW_RE.match(body)
    if m:
        if negated:
            iface.trunk_allow = []
        else:
            arg = m.group(1).strip()
            if arg.lower() == "all":
                # -1 作哨兵，表示 allow-pass vlan all
                iface.trunk_allow = [-1]
            else:
                iface.trunk_allow = expand_vlan_list(arg)
        return

    m = _OSPF_ENABLE_RE.match(body)
    if m:
        if negated:
            iface.ospf_process = None
            iface.ospf_area = None
        else:
            iface.ospf_process = int(m.group(1))
            iface.ospf_area = m.group(2)
        return

    m = _TRAFFIC_FILTER_RE.match(body)
    if m:
        direction = m.group(1).lower()
        acl_number = m.group(2)
        if direction == "inbound":
            iface.acl_in = acl_number
        else:
            iface.acl_out = acl_number
        cfg.acl_bindings.append(
            AclBinding(interface=iface.name, acl_number=acl_number, direction=direction)
        )
        return

    if body_lower == "shutdown":
        iface.admin_up = False
        return


def _parse_ospf_body(
    cfg: Config,
    ctx: _Ctx,
    body: str,
    body_lower: str,
    negated: bool,
    line_no: int,
) -> None:
    proc = ctx.ospf
    if proc is None:
        return

    m = _ROUTER_ID_RE.match(body)
    if m:
        proc.router_id = None if negated else m.group(1)
        return

    m = _AREA_RE.match(body)
    if m:
        area_id = m.group(1)
        if negated:
            proc.areas.pop(area_id, None)
            ctx.area = None
            return
        area = proc.areas.get(area_id)
        if area is None:
            area = OspfArea(area_id=area_id)
            proc.areas[area_id] = area
        ctx.area = area
        # 进入 area 视图后，块仍是 ospf，但内部命令需按 area 处理
        ctx.block = "ospf-area"
        return

    m = _SILENT_RE.match(body)
    if m and not negated:
        # silent-interface 挂在进程层，记录到 __process__ 伪区域
        area = ctx.area
        if area is not None:
            area.silent_interfaces.append(m.group(1))
        return


def _parse_acl_body(acl: Acl, body: str, negated: bool, line_no: int) -> None:
    if negated:
        # `undo rule 5` 只给序号，不带 action
        m = _RULE_UNDO_RE.match(body)
        if m:
            seq = int(m.group(1))
            acl.rules = [r for r in acl.rules if r.seq != seq]
        return

    m = _RULE_RE.match(body)
    if not m:
        return

    seq = int(m.group(1))
    action = m.group(2)
    rest = m.group(3) or ""
    acl.rules.append(_parse_acl_rule(seq, action, rest, line_no))


def _parse_ospf_area_body(
    cfg: Config,
    ctx: _Ctx,
    body: str,
    body_lower: str,
    negated: bool,
    line_no: int,
) -> None:
    """area 视图内的命令（network / quit 回退）。"""
    area = ctx.area
    if area is None:
        return

    m = _NETWORK_RE.match(body)
    if m:
        if negated:
            item = (m.group(1), m.group(2))
            area.networks = [n for n in area.networks if n != item]
        else:
            item = (m.group(1), m.group(2))
            if item not in area.networks:
                area.networks.append(item)
        return


def parse_file(path: str, device_id: str | None = None) -> Config:
    """从文件读取并解析配置。

    编码按 utf-8 → gbk 顺序尝试：国内设备导出的配置文件常见 GBK 编码，
    直接 ignore 会把中文 description 变成空串，造成后续规则误判。
    """
    text: str | None = None
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            with open(path, "r", encoding=enc) as fh:
                text = fh.read()
            break
        except UnicodeDecodeError:
            continue

    if text is None:
        # 全部编码失败：退回容错读取，保证不中断整个批处理
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()

    return parse(text, device_id=device_id or path)
