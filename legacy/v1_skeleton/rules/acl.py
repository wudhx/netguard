"""ACL 类规则：R11 — R14。"""

from __future__ import annotations

from ..models import Config, Finding
from ..netutil import (
    int_to_ip,
    ip_to_int,
    is_valid_wildcard,
    network_of,
)
from .base import Rule, finding


def _wild_to_mask(wild: str) -> str:
    return int_to_ip(0xFFFFFFFF ^ ip_to_int(wild))


def _r11(cfg: Config) -> list[Finding]:
    """前置 deny 覆盖后置 permit 的地址空间。

    判定条件：deny 的源范围包含 permit 的源范围，则 permit 永远不会命中。
    """
    rule = R11
    out: list[Finding] = []
    for acl in cfg.acls.values():
        rules = acl.rules
        for i, deny_rule in enumerate(rules):
            if deny_rule.action != "deny":
                continue
            if not (deny_rule.src and deny_rule.src_wild and is_valid_wildcard(deny_rule.src_wild)):
                continue
            deny_mask = _wild_to_mask(deny_rule.src_wild)
            for permit_rule in rules[i + 1:]:
                if permit_rule.action != "permit":
                    continue
                if not (permit_rule.src and permit_rule.src_wild and is_valid_wildcard(permit_rule.src_wild)):
                    continue
                permit_mask = _wild_to_mask(permit_rule.src_wild)
                try:
                    deny_net = network_of(deny_rule.src, deny_mask)
                    permit_net = network_of(permit_rule.src, permit_mask)
                except ValueError:
                    continue
                if deny_net != permit_net:
                    continue
                # 反掩码更大 = 覆盖范围更大
                if ip_to_int(deny_rule.src_wild) >= ip_to_int(permit_rule.src_wild):
                    out.append(
                        finding(
                            rule,
                            f"ACL {acl.number} 中 rule {deny_rule.seq}（deny）覆盖了 "
                            f"rule {permit_rule.seq}（permit）的源地址范围，后者永远不会生效",
                            line_no=permit_rule.line_no,
                        )
                    )
    return out


def _r12(cfg: Config) -> list[Finding]:
    rule = R12
    out: list[Finding] = []
    for acl in cfg.acls.values():
        for r in acl.rules:
            for label, wild in (("源", r.src_wild), ("目的", r.dst_wild)):
                if wild is None or wild.lower() == "any":
                    continue
                if not is_valid_wildcard(wild):
                    out.append(
                        finding(
                            rule,
                            f"ACL {acl.number} rule {r.seq} 的{label}反掩码非法：{wild}",
                            line_no=r.line_no,
                        )
                    )
    return out


def _r13(cfg: Config) -> list[Finding]:
    rule = R13
    out: list[Finding] = []
    for acl in cfg.acls.values():
        if not acl.rules:
            continue
        if all(r.action == "permit" for r in acl.rules):
            out.append(
                finding(
                    rule,
                    f"ACL {acl.number} 全部为 permit 规则，未显式拒绝管理面或高危流量",
                    line_no=acl.line_no,
                )
            )
    return out


def _r14(cfg: Config) -> list[Finding]:
    rule = R14
    out: list[Finding] = []
    applied = {acl for acl, _iface, _direction in cfg.acl_applications()}
    for number, acl in cfg.acls.items():
        if number not in applied:
            out.append(
                finding(
                    rule,
                    f"ACL {number} 已定义但未应用到任何接口，配置不生效",
                    line_no=acl.line_no,
                )
            )
    return out


R11 = Rule(
    id="R11",
    name="ACL 规则顺序覆盖",
    category="ACL",
    level="A",
    severity="high",
    basis="ACL 匹配顺序语义（自上而下，命中即停）",
    check=_r11,
)

R12 = Rule(
    id="R12",
    name="反掩码非法",
    category="ACL",
    level="A",
    severity="high",
    basis="华为 VRP ACL 语法",
    check=_r12,
)

R13 = Rule(
    id="R13",
    name="ACL 缺少显式拒绝",
    category="ACL",
    level="B",
    severity="medium",
    basis="ACL 安全基线",
    check=_r13,
)

R14 = Rule(
    id="R14",
    name="ACL 未应用",
    category="ACL",
    level="A",
    severity="medium",
    basis="配置有效性",
    check=_r14,
)

RULES = [R11, R12, R13, R14]
