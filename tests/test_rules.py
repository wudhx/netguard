"""规则层单元测试。

分四组：
1. 注册表完整性 —— 12 条规则、ID 唯一、元数据合法
2. 逐规则判定 —— 每条规则一正一反
3. 降级机制 —— `fp_mitigated` 生效、降级理由出现在 message
4. 语料集成 —— 6 份语料的命中集合可回归

## 为什么每条规则都要写「反例」

规则的唯一价值是「报出来的都是真问题」。只写正例的测试能证明规则**会报**，
但不能证明它**不乱报**。误报是这类工具死掉的头号原因——用户被假问题骗两次
就不再看了。所以每条规则至少配一个「几乎一样但不该报」的用例。

## 为什么断言严重度而不只断言条数

严重度是报告排序和用户决策的直接输入。规则误把 HIGH 写成 MEDIUM，
条数对、测试绿、报告照样是错的。所以断言具体到 `(rule_id, severity)`。
"""

from __future__ import annotations

import pytest

from netguard.core.models import Nature, Role, Severity
from netguard.core.parser import parse
from netguard.core.rules import (
    REGISTRY,
    all_rules,
    get_rule,
    rules_for_role,
)

# ===========================================================================
# 1. 注册表完整性
# ===========================================================================

EXPECTED_RULES = {
    "OSPF-001": Severity.HIGH,
    "OSPF-002": Severity.MEDIUM,
    "OSPF-003": Severity.MEDIUM,
    "OSPF-004": Severity.HIGH,
    "ACL-001": Severity.HIGH,
    "ACL-002": Severity.HIGH,
    "ACL-003": Severity.LOW,
    "ACL-004": Severity.BLOCKER,
    "IF-001": Severity.HIGH,
    "IF-002": Severity.MEDIUM,
    "RT-001": Severity.LOW,
    "SEC-001": Severity.HIGH,
}


class TestRegistry:
    def test_rule_count_matches_architecture(self) -> None:
        """架构 §5.4 规划 12 条，代码必须不多不少。"""
        assert len(REGISTRY) == 12

    def test_rule_ids_and_severities(self) -> None:
        actual = {r.id: r.meta.severity for r in all_rules()}
        assert actual == EXPECTED_RULES

    def test_all_rules_sorted_by_id(self) -> None:
        ids = [r.id for r in all_rules()]
        assert ids == sorted(ids)

    def test_duplicate_id_rejected(self) -> None:
        """撞 ID 必须当场炸，否则「哪条规则报的」永久失准。"""
        from netguard.core.models import Needs
        from netguard.core.rules.base import rule

        with pytest.raises(ValueError, match="规则 ID 重复"):

            @rule(
                id="OSPF-001",
                title="重复测试",
                severity=Severity.LOW,
                nature=Nature.DEFECT,
                category="测试",
                needs=Needs.SINGLE_DEVICE,
                applies_to=[Role.CORE],
                doc_ref="测试",
            )
            def _dup(cfg):  # type: ignore[no-untyped-def]
                return []

    def test_every_rule_has_doc_ref_and_category(self) -> None:
        """basis 文案只允许来自元数据，空的 doc_ref 会让报告失去依据。"""
        for r in all_rules():
            assert r.meta.doc_ref.strip(), f"{r.id} 缺 doc_ref"
            assert r.meta.category.strip(), f"{r.id} 缺 category"
            assert r.meta.applies_to, f"{r.id} 未声明 applies_to"

    def test_known_fp_mitigated_not_downgraded(self) -> None:
        """能自动规避误报的规则保留真实严重度（fp_mitigated=True）。"""
        for rid in ("OSPF-001", "ACL-001", "IF-001"):
            meta = get_rule(rid).meta  # type: ignore[union-attr]
            assert meta.known_fp, f"{rid} 应登记 known_fp"
            assert meta.fp_mitigated, f"{rid} 应标记 fp_mitigated"
            assert meta.severity.value > Severity.LOW.value


class TestRoleFilter:
    def test_unknown_role_gets_everything(self) -> None:
        """兜底：角色未知时宁可多查不可空转（架构 §7.3）。"""
        assert len(rules_for_role(Role.UNKNOWN)) == 12

    def test_core_switch_candidates(self) -> None:
        ids = {r.id for r in rules_for_role(Role.CORE)}
        assert "OSPF-004" in ids
        assert len(ids) >= 8

    def test_access_switch_excludes_ospf_area_rules(self) -> None:
        """接入层不跑 OSPF 区域覆盖类判定。"""
        ids = {r.id for r in rules_for_role(Role.ACCESS)}
        assert "OSPF-004" not in ids


# ===========================================================================
# 2. 逐规则判定
# ===========================================================================


def _run(rule_id: str, text: str):
    return get_rule(rule_id).check(parse(text))  # type: ignore[union-attr]


class TestOspfRules:
    def test_ospf001_same_ip_two_areas(self) -> None:
        """同一 IP 落入两个区域的 network 范围。

        注意：OSPF-001 的判据是 **network 语句的覆盖范围**，不是接口上的
        `ospf enable ... area`。前者是区域划分的实际依据，后者在 VRP 里
        是另一种使能方式，二者不能混用来触发本规则。
        """
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.1.1.0 0.0.0.255
 area 0.0.0.1
  network 10.1.1.0 0.0.0.255
"""
        found = _run("OSPF-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH

    def test_ospf001_vrf_downgrades_to_info(self) -> None:
        """同一个 IP 在不同 VRF 里合法共存，不能硬报 HIGH。"""
        cfg = """
ip vpn-instance VPN-A
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.1.1.0 0.0.0.255
 area 0.0.0.1
  network 10.1.1.0 0.0.0.255
"""
        found = _run("OSPF-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.INFO
        assert "VRF" in found[0].message

    def test_ospf001_area_id_normalized(self) -> None:
        """`area 0` 与 `area 0.0.0.0` 是同一区域，不能当成两个而误报。"""
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ospf 1 router-id 1.1.1.1
 area 0
  network 10.1.1.0 0.0.0.255
 area 0.0.0.0
  network 10.1.1.0 0.0.0.255
"""
        assert _run("OSPF-001", cfg) == []

    def test_ospf002_network_without_interface(self) -> None:
        cfg = """
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 192.168.99.0 0.0.0.255
"""
        found = _run("OSPF-002", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.MEDIUM

    def test_ospf002_network_matching_interface_ok(self) -> None:
        """有接口落在 network 范围内就不该报。"""
        cfg = """
interface GigabitEthernet0/0/1
 ip address 192.168.99.1 255.255.255.0
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 192.168.99.0 0.0.0.255
"""
        assert _run("OSPF-002", cfg) == []

    def test_ospf003_router_id_missing(self) -> None:
        cfg = """
ospf 1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
"""
        found = _run("OSPF-003", cfg)
        assert len(found) == 1

    def test_ospf003_router_id_reserved_zero(self) -> None:
        cfg = """
ospf 1 router-id 0.0.0.0
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
"""
        assert len(_run("OSPF-003", cfg)) == 1

    def test_ospf003_valid_router_id_ok(self) -> None:
        cfg = """
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
"""
        assert _run("OSPF-003", cfg) == []

    def test_ospf004_interface_not_covered(self) -> None:
        cfg = """
interface GigabitEthernet0/0/1
 ip address 172.16.5.1 255.255.255.0
 ospf enable 1 area 0.0.0.0
ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
"""
        found = _run("OSPF-004", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH


class TestAclRules:
    def test_acl001_deny_shadows_permit(self) -> None:
        cfg = """
acl number 3000
 rule 5 deny ip source 10.0.0.0 0.0.0.255 destination any
 rule 10 permit ip source 10.0.0.5 0.0.0.0 destination any
"""
        found = _run("ACL-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH

    def test_acl001_unrelated_permit_ok(self) -> None:
        """permit 的源地址不在 deny 覆盖范围内就不该报。"""
        cfg = """
acl number 3000
 rule 5 deny ip source 10.0.0.0 0.0.0.255 destination any
 rule 10 permit ip source 192.168.1.0 0.0.0.255 destination any
"""
        assert _run("ACL-001", cfg) == []

    def test_acl001_vrf_downgrades_to_info(self) -> None:
        cfg = """
ip vpn-instance VPN-A
acl number 3000
 rule 5 deny ip source 10.0.0.0 0.0.0.255 destination any
 rule 10 permit ip source 10.0.0.5 0.0.0.0 destination any
"""
        found = _run("ACL-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.INFO
        assert "VRF" in found[0].message

    def test_acl002_invalid_wildcard(self) -> None:
        cfg = """
acl number 3000
 rule 5 permit ip source 10.0.0.0 0.0.255.0 destination any
"""
        found = _run("ACL-002", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH

    def test_acl002_valid_wildcard_ok(self) -> None:
        cfg = """
acl number 3000
 rule 5 permit ip source 10.0.0.0 0.0.0.255 destination any
"""
        assert _run("ACL-002", cfg) == []

    def test_acl003_not_referenced(self) -> None:
        cfg = """
acl number 3000
 rule 5 permit ip
"""
        found = _run("ACL-003", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.LOW

    def test_acl003_referenced_ok(self) -> None:
        cfg = """
acl number 3000
 rule 5 permit ip
interface GigabitEthernet0/0/1
 traffic-filter inbound acl 3000
"""
        assert _run("ACL-003", cfg) == []

    def test_acl004_empty_acl_applied(self) -> None:
        cfg = """
acl number 3000
interface GigabitEthernet0/0/1
 traffic-filter inbound acl 3000
"""
        found = _run("ACL-004", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.BLOCKER

    def test_acl004_deny_any_only_applied(self) -> None:
        """只写 deny any 的空壳 ACL 挂上接口 = 全阻断，与空 ACL 等价。"""
        cfg = """
acl number 3000
 rule 5 deny ip
interface GigabitEthernet0/0/1
 traffic-filter inbound acl 3000
"""
        found = _run("ACL-004", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.BLOCKER

    def test_acl004_not_applied_ok(self) -> None:
        cfg = "acl number 3000\n"
        assert _run("ACL-004", cfg) == []


class TestIfaceRules:
    def test_if001_identical_ip(self) -> None:
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
interface GigabitEthernet0/0/2
 ip address 10.1.1.1 255.255.255.0
"""
        found = _run("IF-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH

    def test_if001_subnet_overlap(self) -> None:
        """不同 IP 但网段重叠，同样是冲突。"""
        cfg = """
interface Vlanif10
 ip address 192.168.10.1 255.255.255.0
interface Vlanif20
 ip address 192.168.10.2 255.255.255.0
"""
        found = _run("IF-001", cfg)
        assert len(found) == 1
        assert "192.168.10.1" in found[0].message

    def test_if001_different_subnet_ok(self) -> None:
        cfg = """
interface Vlanif10
 ip address 192.168.10.1 255.255.255.0
interface Vlanif20
 ip address 192.168.20.1 255.255.255.0
"""
        assert _run("IF-001", cfg) == []

    def test_if001_shutdown_still_conflict(self) -> None:
        """shutdown 只是管理态关闭，IP 仍然占着地址，冲突不消失。"""
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
interface GigabitEthernet0/0/2
 ip address 10.1.1.1 255.255.255.0
 shutdown
"""
        assert len(_run("IF-001", cfg)) == 1

    def test_if002_l3_intent_without_ip(self) -> None:
        cfg = """
interface Vlanif10
 description server
"""
        found = _run("IF-002", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.MEDIUM

    def test_if002_physical_port_without_ip_ok(self) -> None:
        """物理口不配 IP 是正常的（二层口），不能报。"""
        cfg = """
interface GigabitEthernet0/0/1
 port link-type trunk
"""
        assert _run("IF-002", cfg) == []


class TestRouteAndSecurityRules:
    def test_rt001_nexthop_not_direct(self) -> None:
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ip route-static 192.168.0.0 255.255.0.0 172.16.1.1
"""
        found = _run("RT-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.LOW

    def test_rt001_direct_nexthop_ok(self) -> None:
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ip route-static 192.168.0.0 255.255.0.0 10.1.1.2
"""
        assert _run("RT-001", cfg) == []

    def test_rt001_recursive_nexthop_ok(self) -> None:
        """下一跳虽不直连，但被另一条静态路由覆盖，不该报。"""
        cfg = """
interface GigabitEthernet0/0/1
 ip address 10.1.1.1 255.255.255.0
ip route-static 172.16.0.0 255.255.0.0 10.1.1.2
ip route-static 192.168.0.0 255.255.0.0 172.16.1.1
"""
        assert _run("RT-001", cfg) == []

    def test_sec001_telnet_without_acl(self) -> None:
        cfg = """
telnet server enable
user-interface vty 0 4
 protocol inbound telnet
"""
        found = _run("SEC-001", cfg)
        assert len(found) == 1
        assert found[0].severity is Severity.HIGH

    def test_sec001_ssh_only_ok(self) -> None:
        cfg = """
user-interface vty 0 4
 protocol inbound ssh
"""
        assert _run("SEC-001", cfg) == []

    def test_sec001_permit_any_acl_is_not_restriction(self) -> None:
        """绑了 permit any 的 ACL 等于没绑，仍应报。"""
        cfg = """
telnet server enable
acl number 2000
 rule 5 permit source any
user-interface vty 0 4
 protocol inbound telnet
 acl 2000 inbound
"""
        assert len(_run("SEC-001", cfg)) == 1


# ===========================================================================
# 3. Finding 通用性质
# ===========================================================================


class TestFindingInvariants:
    @pytest.mark.parametrize("rule_id", sorted(EXPECTED_RULES))
    def test_every_finding_has_basis(self, rule_id: str) -> None:
        """basis 必须来��规则元数据——事实层由规则生成，模型不参与。"""
        rule = get_rule(rule_id)
        assert rule is not None
        corpus = {
            "OSPF-001": "interface GigabitEthernet0/0/1\n ip address 10.1.1.1 255.255.255.0\nospf 1 router-id 1.1.1.1\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n area 0.0.0.1\n  network 10.1.1.0 0.0.0.255\n",
            "OSPF-002": "ospf 1 router-id 1.1.1.1\n area 0.0.0.0\n  network 192.168.99.0 0.0.0.255\n",
            "OSPF-003": "ospf 1\n",
            "OSPF-004": "interface GigabitEthernet0/0/1\n ip address 172.16.5.1 255.255.255.0\n ospf enable 1 area 0\nospf 1 router-id 1.1.1.1\n area 0.0.0.0\n  network 10.0.0.0 0.0.0.255\n",
            "ACL-001": "acl number 3000\n rule 5 deny ip source 10.0.0.0 0.0.0.255 destination any\n rule 10 permit ip source 10.0.0.5 0.0.0.0 destination any\n",
            "ACL-002": "acl number 3000\n rule 5 permit ip source 10.0.0.0 0.0.255.0 destination any\n",
            "ACL-003": "acl number 3000\n rule 5 permit ip\n",
            "ACL-004": "acl number 3000\ninterface GigabitEthernet0/0/1\n traffic-filter inbound acl 3000\n",
            "IF-001": "interface Vlanif10\n ip address 192.168.10.1 255.255.255.0\ninterface Vlanif20\n ip address 192.168.10.2 255.255.255.0\n",
            "IF-002": "interface Vlanif10\n description server\n",
            "RT-001": "interface GigabitEthernet0/0/1\n ip address 10.1.1.1 255.255.255.0\nip route-static 192.168.0.0 255.255.0.0 172.16.1.1\n",
            "SEC-001": "telnet server enable\nuser-interface vty 0 4\n protocol inbound telnet\n",
        }[rule_id]
        found = rule.check(parse(corpus))
        assert found, f"{rule_id} 在自检语料上未命中"
        for f in found:
            assert f.basis == rule.meta.doc_ref
            assert f.rule_id == rule_id
            assert len(f.evidence) <= 200

    def test_evidence_truncated(self) -> None:
        """evidence 超长截断，避免报告被一条脏数据撑爆。"""
        from netguard.core.models import Finding

        f = Finding(
            rule_id="X-001",
            severity=Severity.LOW,
            nature=Nature.DEFECT,
            location="接口 GigabitEthernet0/0/1",
            message="测试",
            evidence="A" * 500,
            basis="测试",
        )
        assert len(f.evidence) <= 200


# ===========================================================================
# 4. 语料集成（回归基线）
# ===========================================================================


CORPUS_EXPECTED = {
    "case01_core_switch.txt": {
        "ACL-001",
        "ACL-003",
        "IF-001",
        "OSPF-001",
        "OSPF-003",
        "SEC-001",
    },
    "case02_border_router.txt": {"ACL-001", "ACL-003", "OSPF-001"},
    "case03_access_switch.txt": {"ACL-003", "OSPF-003"},
    "case04_ospf_errors.txt": {"OSPF-002", "OSPF-003", "OSPF-004"},
    "case05_acl_errors.txt": {"ACL-002", "ACL-003", "ACL-004"},
    "case06_interface_errors.txt": {"IF-001", "IF-002"},
}


class TestCorpusIntegration:
    @pytest.mark.parametrize("filename", sorted(CORPUS_EXPECTED))
    def test_hit_set(self, filename: str) -> None:
        """6 份语料的命中规则集合，作为回归基线。

        这组断言不追求「命中越多越好」——反过来，任何一次命中增加都要
        人工确认是不是新增了误报。所以基线是**锁死**的，改它必须说明理由。
        """
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "corpus" / filename
        cfg = parse(path.read_text(encoding="utf-8"), device_id=filename)
        hits = set()
        for rule in all_rules():
            for _ in rule.check(cfg):
                hits.add(rule.id)
        assert hits == CORPUS_EXPECTED[filename]
