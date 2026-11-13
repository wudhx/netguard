"""ACL 规则 ACL-001 ~ ACL-004。

## 一个必须先说明的边界（§5.6 第 2 类误报）

华为 ACL 未匹配任何规则时的默认动作**取决于调用它的模块**：

- `traffic-filter` 默认 **deny**
- NAT / 策略路由默认 **permit**

本工具只分析「显式规则之间的覆盖关系」，不对隐式默认动作下断言。
因此 ACL-004 判断「仅含 deny any」时，报告的是「引用即全阻断」这一
显式规则事实，不推断「没有 permit 所以一定阻断」。
"""

from __future__ import annotations

from ..models import Acl, AclRule, Config, Finding, Nature, Needs, Role, Severity
from .. import netutil
from .base import finding, rule

# 角色适用集按运维常识推导，非 §5.4 原文规定（§5.4 只列规则与严重度，
# 未规定 applies_to）。推导依据见下方各规则注释。
_ALL_ROLES = (Role.CORE, Role.AGG, Role.BORDER, Role.ACCESS)
# 排除接入层：接入交换机上的 ACL 多半由上层统一下发模板，本机定义但本地
# 不引用是常见形态，报「未引用」在接入层上是噪声而非缺陷。
_NOT_ACCESS = (Role.CORE, Role.AGG, Role.BORDER)


def _norm_seq(rules: list[AclRule]) -> list[AclRule]:
    """按 seq 升序。

    设备侧真正的匹配顺序由 seq 决定，与配置文件里的书写顺序无关。
    不排序就分析覆盖关系，会在「配置文件顺序与 seq 不一致」时全错。
    """
    return sorted(rules, key=lambda r: r.seq)


def _addr_covers(rule_a: AclRule, rule_b: AclRule, side: str) -> bool:
    """判断规则 A 在 source/destination 维度上是否覆盖规则 B。

    覆盖条件（两维都要满足）：
    1. 网络地址落在对方网段内
    2. A 的反掩码范围 ≥ B 的反掩码范围（即 A 的网段更宽）
    """
    if side == "src":
        a_addr, a_wild = rule_a.source, rule_a.source_wildcard
        b_addr, b_wild = rule_b.source, rule_b.source_wildcard
    else:
        a_addr, a_wild = rule_a.destination, rule_a.destination_wildcard
        b_addr, b_wild = rule_b.destination, rule_b.destination_wildcard

    # 未写地址 = any，覆盖一切
    if a_addr is None:
        return True
    if b_addr is None:
        # 对方是 any，自己不是 → 不可能覆盖
        return False

    if not (netutil.is_ipv4(a_addr) and netutil.is_ipv4(b_addr)):
        return False
    if not (netutil.is_valid_wildcard(a_wild or "0.0.0.0") and netutil.is_valid_wildcard(b_wild or "0.0.0.0")):
        return False

    a_wild = a_wild or "0.0.0.0"
    b_wild = b_wild or "0.0.0.0"

    if not netutil.wildcard_covers(a_wild, b_wild):
        return False

    # A 的网段必须真的包含 B 的地址
    return netutil.ip_in_network(b_addr, a_addr, a_wild)


def _protocol_covers(a: AclRule, b: AclRule) -> bool:
    """协议维度覆盖：`ip` 覆盖所有；否则必须同协议。"""
    if a.protocol == "ip":
        return True
    return a.protocol == b.protocol


def _port_covers(a: AclRule, b: AclRule) -> bool:
    """端口维度：A 未限定端口则覆盖 B；都限定则须相同。"""
    if a.dst_port is None:
        return True
    return a.dst_port == b.dst_port


def _a_covers_b(a: AclRule, b: AclRule) -> bool:
    """规则 a 是否完全覆盖规则 b（使 b 永不生效）。"""
    return (
        _addr_covers(a, b, "src")
        and _addr_covers(a, b, "dst")
        and _protocol_covers(a, b)
        and _port_covers(a, b)
    )


def _bound_acls(cfg: Config) -> set[str]:
    return {b.acl_number for b in cfg.acl_bindings}


@rule(
    id="ACL-001",
    title="前置 deny 覆盖后置 permit",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="acl",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ALL_ROLES,
    doc_ref="华为 VRP ACL 匹配顺序：自上而下，首条匹配即生效",
    known_fp="多 VRF 场景下同地址段可合法共存；检测到 ip vpn-instance 时降为 INFO",
    fp_mitigated=True,
    examples={
        "positive": "corpus/case01_core_switch.txt",
        "negative": "corpus/case02_border_router.txt",
    },
)
def deny_shadow_permit(cfg: Config) -> list[Finding]:
    """前置 deny 规则在范围内的所有维度上覆盖了后置 permit。

    后果：那条 permit 永远不会生效。配置看起来「放了行」，实际仍然被拒绝——
    这是排查「明明加了白名单还是不通」时最常见的根因。

    只报 deny→permit 方向。permit 覆盖后续 deny 虽然也让后者失效，
    但那是「放得过宽」，不是「误阻断」，风险性质不同，Phase 1 不混在一起报。
    """
    out: list[Finding] = []
    mitigated = cfg.has_vrf

    for number, acl in sorted(cfg.acls.items()):
        rules = _norm_seq(acl.rules)
        for i, front in enumerate(rules):
            if front.action != "deny":
                continue
            for back in rules[i + 1:]:
                if back.action != "permit":
                    continue
                if not _a_covers_b(front, back):
                    continue

                evidence = (
                    f"rule {front.seq} deny {front.protocol}"
                    f"{' source ' + front.source + ' ' + (front.source_wildcard or '') if front.source else ''}"
                    f"  ← 覆盖 →  "
                    f"rule {back.seq} permit {back.protocol}"
                    f"{' source ' + back.source + ' ' + (back.source_wildcard or '') if back.source else ''}"
                )
                message = (
                    f"ACL {number} 的 rule {front.seq}（deny）覆盖了"
                    f" rule {back.seq}（permit），后者永不生效"
                )
                if mitigated:
                    # 降级理由必须写在消息里，不能只藏在 evidence——
                    # 报告正文读的是 message，读者看不到 INFO 的原因会以为规则出错了。
                    evidence += "（配置含 ip vpn-instance，ACL 作用域可能不同，仅供参考）"
                    message += "［因配置含 VRF，暂降为提示］"

                out.append(
                    finding(
                        deny_shadow_permit.meta,
                        location=f"acl {number} rule {back.seq}",
                        message=message,
                        evidence=evidence,
                        line_no=back.line_no,
                        hint=f"把 rule {front.seq} 的 deny 范围收窄，或把 permit 提到更前",
                        severity=Severity.INFO if mitigated else None,
                    )
                )

    return out


@rule(
    id="ACL-002",
    title="反掩码非法 / 非连续通配符",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="acl",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ALL_ROLES,
    doc_ref="华为 VRP ACL 语法：反掩码取反后必须是连续掩码",
    known_fp="",
    examples={
        "positive": "corpus/case05_acl_errors.txt",
        "negative": "corpus/case01_core_switch.txt",
    },
)
def invalid_wildcard(cfg: Config) -> list[Finding]:
    """ACL 规则里的反掩码不合法。

    反掩码取反后必须是连续掩码（如 0.0.0.255 → 255.255.255.0）。
    `0.0.255.0` 这类非连续值设备可能接受，但匹配语义是「按位比较」，
    产出的地址集与配置者的直觉不符——几乎总是写错了。
    """
    out: list[Finding] = []

    for number, acl in sorted(cfg.acls.items()):
        for r in _norm_seq(acl.rules):
            for field, addr, wild in (
                ("source", r.source, r.source_wildcard),
                ("destination", r.destination, r.destination_wildcard),
            ):
                if addr is None:
                    continue
                if wild is None:
                    continue
                if netutil.is_valid_wildcard(wild):
                    continue

                out.append(
                    finding(
                        invalid_wildcard.meta,
                        location=f"acl {number} rule {r.seq}",
                        message=(
                            f"ACL {number} rule {r.seq} 的 {field} 反掩码 `{wild}` "
                            f"取反后不是连续掩码"
                        ),
                        evidence=f"rule {r.seq} {r.action} {r.protocol} {field} {addr} {wild}",
                        line_no=r.line_no,
                        hint="改为连续反掩码（如 0.0.0.255 对应 /24）",
                    )
                )

    return out


@rule(
    id="ACL-003",
    title="ACL 已定义但未被引用",
    severity=Severity.LOW,
    nature=Nature.DEFECT,
    category="acl",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_NOT_ACCESS,
    doc_ref="配置有效性：未绑定的 ACL 不产生任何流量控制效果",
    known_fp="",
    examples={
        "positive": "corpus/case02_border_router.txt",
        "negative": "corpus/case01_core_switch.txt",
    },
)
def acl_not_referenced(cfg: Config) -> list[Finding]:
    """定义了 ACL 但没有任何接口或模块引用它。

    这类配置是「以为设了防护，其实没生效」——比没配更危险，
    因为它给了人虚假的安全感。
    """
    out: list[Finding] = []
    bound = _bound_acls(cfg)

    for number, acl in sorted(cfg.acls.items()):
        if number in bound:
            continue
        out.append(
            finding(
                acl_not_referenced.meta,
                location=f"acl {number}",
                message=f"ACL {number} 已定义但未被任何接口引用",
                evidence=f"acl {number}（含 {len(acl.rules)} 条规则）",
                hint="确认是否需要绑定到接口，或删除这条无效配置",
            )
        )

    return out


@rule(
    id="ACL-004",
    title="ACL 为空或仅含 deny any 却被引用",
    severity=Severity.BLOCKER,
    nature=Nature.DEFECT,
    category="acl",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ALL_ROLES,
    doc_ref="traffic-filter 调用空 ACL 或全 deny ACL 时，该方向流量全部被丢弃",
    known_fp="",
    examples={
        "positive": "corpus/case05_acl_errors.txt",
        "negative": "corpus/case02_border_router.txt",
    },
)
def empty_acl_applied(cfg: Config) -> list[Finding]:
    """被引用的 ACL 是空的，或只有一条 deny any。

    `traffic-filter` 引用空 ACL 时，未匹配任何规则的流量按模块默认动作为
    deny——等价于把这个方向全部阻断。这是能直接打瘫业务的一级故障，
    却常常是「先把 ACL 绑上去，规则以后再加」这种操作留下的。

    只对 `traffic-filter` 绑定判定，因为它的默认动作确定是 deny；
    其他模块（NAT/策略路由）默认 permit，不能套用同一结论（§5.6 第 2 类）。
    """
    out: list[Finding] = []

    traffic_bound = {
        b.acl_number: b for b in cfg.acl_bindings if b.direction in ("inbound", "outbound")
    }

    for number, binding in sorted(traffic_bound.items()):
        acl = cfg.acls.get(number)
        if acl is None:
            # 引用了不存在的 ACL：设备侧通常拒绝下发，配置里不应出现。
            # 出现了说明是手工拼接或解析遗漏，报出来比静默忽略好。
            out.append(
                finding(
                    empty_acl_applied.meta,
                    location=f"interface {binding.interface}",
                    message=(
                        f"接口 {binding.interface} 的 {binding.direction} 方向"
                        f"引用了不存在的 ACL {number}"
                    ),
                    evidence=f"traffic-filter {binding.direction} acl {number}",
                    hint="创建该 ACL 或修正引用编号",
                )
            )
            continue

        if acl.is_empty():
            out.append(
                finding(
                    empty_acl_applied.meta,
                    location=f"interface {binding.interface}",
                    message=(
                        f"接口 {binding.interface} 的 {binding.direction} 方向引用了"
                        f"空 ACL {number}，该方向流量将全部被丢弃"
                    ),
                    evidence=f"traffic-filter {binding.direction} acl {number}（ACL 无任何 rule）",
                    hint="补充放行规则，或先解除绑定",
                )
            )
            continue

        if acl.only_deny_any():
            seq = acl.rules[0].seq
            out.append(
                finding(
                    empty_acl_applied.meta,
                    location=f"interface {binding.interface}",
                    message=(
                        f"接口 {binding.interface} 的 {binding.direction} 方向引用了"
                        f"仅含 `deny any`（rule {seq}）的 ACL {number}，该方向流量将全部被丢弃"
                    ),
                    evidence=f"acl {number}: rule {seq} {acl.rules[0].action} {acl.rules[0].protocol}"
                    f"；traffic-filter {binding.direction} acl {number}",
                    line_no=acl.rules[0].line_no,
                    hint="在 deny 之前补充需要放行的规则",
                )
            )

    return out
