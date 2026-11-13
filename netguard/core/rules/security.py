"""安全基线规则 SEC-001。

Phase 1 只有一条。理由：安全类规则最容易滑向「泛泛的最佳实践清单」，
那样既测不准也没完没了。这里只收一条能确定性判定、且后果明确的。

其余安全项（SNMP 团体字明文、弱口令、AAA 未启用等）列入 ROADMAP.md，
理由见该文件。
"""

from __future__ import annotations

from ..models import Config, Finding, Nature, Needs, Role, Severity
from .base import finding, rule

# 适用于全部角色，不按 Role 过滤。
# 例外说明：接入交换机往往位于物理边界内、由上游设备统一管控，有人会主张
# 「接入层开 Telnet 风险低」。但这个主张不成立——接入交换机的 VTY 一旦被
# 拿到，攻击者即获得一个内网跳板，且明文口令可被嗅探。等保 2.0 的身份鉴别
# 要求不因设备层级而降级。因此本规则对全部角色保留。
_ALL_ROLES = (Role.CORE, Role.AGG, Role.BORDER, Role.ACCESS)

# 这些 ACL 编号段常被用作「管理面源地址限制」
# 2000-2999 基本 ACL、3000-3999 高级 ACL
_MGMT_ACL_MIN = 2000
_MGMT_ACL_MAX = 3999


@rule(
    id="SEC-001",
    title="开启 Telnet 且未限制源地址",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,
    category="security",
    needs=Needs.SINGLE_DEVICE,
    applies_to=_ALL_ROLES,
    doc_ref="等保 2.0 身份鉴别：远程管理应使用加密协议，明文协议须限制访问源",
    known_fp="",
    examples={
        "positive": "corpus/case01_core_switch.txt",
        "negative": "corpus/case03_access_switch.txt",
    },
)
def telnet_without_restriction(cfg: Config) -> list[Finding]:
    """Telnet 服务开启，但没有任何 ACL 限制管理面访问源。

    判定分两步，缺一不可：

    1. `telnet server enable` 存在（全局层面明文协议被允许）
    2. 没有可用的源地址限制

    第 2 步的判据必须是「有 ACL 且该 ACL 有实际限制作用」，不能只看
    「有没有 ACL」——绑了一个 permit any 的 ACL 等于没绑。
    """
    if not cfg.telnet_enabled:
        return []

    bound = {b.acl_number for b in cfg.acl_bindings}

    # 找出真正有限制作用的 ACL：被绑定，且不是「全放行」
    effective_restrictions: list[str] = []
    for number in sorted(bound):
        acl = cfg.acls.get(number)
        if acl is None or acl.is_empty():
            continue
        # 只含 permit 且无任何地址限定 → 等价于放行全部，不算限制
        if all(
            r.action == "permit" and r.source is None
            for r in acl.rules
        ):
            continue
        effective_restrictions.append(number)

    if effective_restrictions:
        return []

    # 判断是否存在「限制形态」的 ACL 但没绑上——这种要给出更精确的提示
    unbound_restrictive = [
        number
        for number, acl in sorted(cfg.acls.items())
        if number not in bound
        and not acl.is_empty()
        and any(r.action == "deny" for r in acl.rules)
    ]

    hint = "关闭 Telnet，改用 SSH；若必须保留，绑定一条限制管理源的 ACL"
    if unbound_restrictive:
        hint = (
            f"检测到 ACL {', '.join(unbound_restrictive)} 含 deny 规则但未绑定到接口，"
            f"确认是否本意用于限制管理面；否则关闭 Telnet 改用 SSH"
        )

    return [
        finding(
            telnet_without_restriction.meta,
            location="telnet server enable",
            message=(
                "Telnet 服务已开启，但未通过 ACL 限制访问源地址"
                "（明文传输，凭据可被嗅探）"
            ),
            evidence=_build_evidence(cfg),
            hint=hint,
        )
    ]


def _build_evidence(cfg: Config) -> str:
    parts = ["telnet server enable"]
    if cfg.acl_bindings:
        parts.append(
            "已绑定 ACL：" + "、".join(sorted({b.acl_number for b in cfg.acl_bindings}))
        )
    else:
        parts.append("无任何 ACL 绑定")
    return "；".join(parts)
