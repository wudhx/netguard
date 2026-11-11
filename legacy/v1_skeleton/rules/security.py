"""设备安全基线规则：R20。"""

from __future__ import annotations

from ..models import Config, Finding
from .base import Rule, finding


def _r20(cfg: Config) -> list[Finding]:
    rule = R20
    out: list[Finding] = []
    if cfg.telnet_enabled:
        out.append(
            finding(
                rule,
                "设备启用了 Telnet 明文远程管理，凭据与配置内容可被嗅探",
                severity="high",
            )
        )
    if not cfg.ssh_enabled:
        out.append(
            finding(
                rule,
                "未启用 SSH（stelnet server enable），缺少加密远程管理通道",
                severity="medium",
            )
        )
    weak = [c for c in cfg.snmp_communities if c.lower() in ("public", "private", "snmp")]
    if weak:
        out.append(
            finding(
                rule,
                f"SNMP 团体名使用默认弱口令：{', '.join(weak)}",
                severity="high",
            )
        )
    return out


R20 = Rule(
    id="R20",
    name="远程管理安全基线",
    category="安全",
    level="A",
    severity="high",
    basis="等保 2.0 身份鉴别与访问控制要求",
    check=_r20,
)

RULES = [R20]
