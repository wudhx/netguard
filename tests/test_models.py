"""四个枚举与数据模型的单元测试。

重点验证架构中写明的硬约束：
1. known_fp 非空时 severity 最高只能是 LOW（§5.1）
2. UNKNOWN 角色对任何规则都放行（§7.3 兜底）
3. Finding.evidence 超过 200 字截断（§4.2）
4. RuleMeta 不可变（frozen）
"""

from __future__ import annotations

import pytest

from netguard.core.models import (
    Acl,
    AclBinding,
    AclRule,
    Config,
    Finding,
    Interface,
    Nature,
    Needs,
    OspfArea,
    OspfProcess,
    Role,
    RuleMeta,
    Severity,
    StaticRoute,
)


def _meta(**kw) -> RuleMeta:
    base = dict(
        id="OSPF-001",
        title="同一接口 IP 被多个 Area 的 network 宣告",
        severity=Severity.HIGH,
        nature=Nature.DEFECT,
        category="ospf",
        needs=Needs.SINGLE_DEVICE,
        applies_to=frozenset({Role.CORE, Role.AGG}),
        doc_ref="OSPF 区域划分原则",
    )
    base.update(kw)
    return RuleMeta(**base)


class TestSeverityOrdering:
    def test_numeric_order(self) -> None:
        assert Severity.BLOCKER.value > Severity.HIGH.value > Severity.MEDIUM.value
        assert Severity.MEDIUM.value > Severity.LOW.value > Severity.INFO.value

    def test_sort_desc(self) -> None:
        items = [Severity.LOW, Severity.BLOCKER, Severity.MEDIUM, Severity.INFO, Severity.HIGH]
        ordered = sorted(items, key=lambda s: s.value, reverse=True)
        assert ordered == [
            Severity.BLOCKER, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
        ]


class TestNatureNeedsRole:
    def test_nature_values(self) -> None:
        assert Nature.DEFECT.value == "defect"
        assert Nature.RECOMMENDATION.value == "recommendation"

    def test_needs_values(self) -> None:
        assert Needs.SINGLE_DEVICE.value == "single"
        assert Needs.MULTI_DEVICE.value == "multi"
        assert Needs.TOPOLOGY.value == "topology"

    def test_role_count(self) -> None:
        assert len(list(Role)) == 5


class TestRuleMetaConstraint:
    def test_known_fp_with_high_severity_rejected(self) -> None:
        """§5.1 硬约束：known_fp 非空时 severity 最高只能 LOW。"""
        with pytest.raises(ValueError, match="known_fp"):
            _meta(severity=Severity.HIGH, known_fp="多 VRF 场景可合法共存")

    def test_known_fp_with_low_severity_ok(self) -> None:
        m = _meta(severity=Severity.LOW, known_fp="多 VRF 场景可合法共存")
        assert m.severity is Severity.LOW

    def test_known_fp_empty_with_high_ok(self) -> None:
        m = _meta(severity=Severity.BLOCKER, known_fp="")
        assert m.severity is Severity.BLOCKER

    def test_frozen(self) -> None:
        m = _meta()
        with pytest.raises(Exception):
            m.id = "CHANGED"  # type: ignore[misc]


class TestAppliesToRole:
    def test_member(self) -> None:
        assert _meta().applies_to_role(Role.CORE) is True

    def test_non_member(self) -> None:
        assert _meta().applies_to_role(Role.ACCESS) is False

    def test_unknown_always_true(self) -> None:
        """§7.3 兜底：UNKNOWN 角色返回全量候选，宁可多查不可空转。"""
        assert _meta().applies_to_role(Role.UNKNOWN) is True

    def test_unknown_true_even_if_set_empty(self) -> None:
        m = _meta(applies_to=frozenset())
        assert m.applies_to_role(Role.UNKNOWN) is True
        assert m.applies_to_role(Role.CORE) is False


class TestRuleMetaSerialize:
    def test_to_dict_keys(self) -> None:
        d = _meta().to_dict()
        assert set(d) == {
            "id", "title", "severity", "nature", "category",
            "needs", "applies_to", "doc_ref", "known_fp",
        }
        assert d["severity"] == "HIGH"
        assert d["nature"] == "defect"
        assert d["applies_to"] == ["agg", "core"]


class TestFinding:
    def test_key(self) -> None:
        f = Finding(
            rule_id="ACL-001", severity=Severity.HIGH, nature=Nature.DEFECT,
            location="interface GE0/0/1", message="m", evidence="e", basis="b",
        )
        assert f.key == "ACL-001@interface GE0/0/1"

    def test_evidence_truncated(self) -> None:
        f = Finding(
            rule_id="X", severity=Severity.LOW, nature=Nature.DEFECT,
            location="l", message="m", evidence="A" * 500, basis="b",
        )
        assert len(f.evidence) == 201  # 200 + 省略号
        assert f.evidence.endswith("…")

    def test_evidence_short_untouched(self) -> None:
        f = Finding(
            rule_id="X", severity=Severity.LOW, nature=Nature.DEFECT,
            location="l", message="m", evidence="short", basis="b",
        )
        assert f.evidence == "short"

    def test_to_dict(self) -> None:
        f = Finding(
            rule_id="OSPF-003", severity=Severity.MEDIUM, nature=Nature.DEFECT,
            location="ospf 1", message="router-id 未配置", evidence="ospf 1",
            basis="华为 VRP 配置指南", line_no=12,
        )
        d = f.to_dict()
        assert d["severity"] == "MEDIUM"
        assert d["nature"] == "defect"
        assert d["line_no"] == 12


class TestInterface:
    def test_is_l3(self) -> None:
        assert Interface(name="GE0/0/1", ip="10.1.1.1", mask="255.255.255.0").is_l3 is True
        assert Interface(name="GE0/0/2").is_l3 is False

    def test_has_ip_needs_both(self) -> None:
        assert Interface(name="x", ip="10.1.1.1").has_ip is False
        assert Interface(name="x", mask="255.255.255.0").has_ip is False


class TestConfigHelpers:
    def _cfg(self) -> Config:
        cfg = Config(device_id="dev1", hostname="CORE-1")
        cfg.interfaces["GE0/0/1"] = Interface(
            name="GE0/0/1", ip="10.1.1.1", mask="255.255.255.0", ospf_area="0"
        )
        cfg.interfaces["GE0/0/2"] = Interface(name="GE0/0/2")  # 二层口
        cfg.interfaces["Vlanif10"] = Interface(
            name="Vlanif10", ip="10.10.10.1", mask="255.255.255.0"
        )
        return cfg

    def test_l3_interfaces(self) -> None:
        names = sorted(i.name for i in self._cfg().l3_interfaces())
        assert names == ["GE0/0/1", "Vlanif10"]

    def test_has_default_route(self) -> None:
        cfg = self._cfg()
        assert cfg.has_default_route() is False
        cfg.static_routes.append(StaticRoute(dest="0.0.0.0", mask="0.0.0.0", next_hop="1.1.1.1"))
        assert cfg.has_default_route() is True

    def test_ospf_area_of_interface(self) -> None:
        cfg = self._cfg()
        assert cfg.ospf_area_of_interface("GE0/0/1") == "0"
        assert cfg.ospf_area_of_interface("GE0/0/2") is None
        assert cfg.ospf_area_of_interface("NOPE") is None

    def test_areas_declaring(self) -> None:
        cfg = self._cfg()
        proc = OspfProcess(process_id=1, router_id="1.1.1.1")
        proc.areas["0"] = OspfArea(
            area_id="0", networks=[("10.1.1.0", "0.0.0.255")]
        )
        proc.areas["1"] = OspfArea(
            area_id="1", networks=[("10.10.10.0", "0.0.0.255")]
        )
        cfg.ospf[1] = proc

        assert cfg.areas_declaring(cfg.interfaces["GE0/0/1"]) == ["0"]
        assert cfg.areas_declaring(cfg.interfaces["Vlanif10"]) == ["1"]
        assert cfg.areas_declaring(cfg.interfaces["GE0/0/2"]) == []

    def test_bound_acls(self) -> None:
        cfg = self._cfg()
        cfg.acl_bindings.append(AclBinding(interface="GE0/0/1", acl_number="3000", direction="inbound"))
        m = cfg.bound_acls()
        assert list(m) == ["GE0/0/1"]
        assert m["GE0/0/1"][0].acl_number == "3000"


class TestAcl:
    def test_is_empty(self) -> None:
        assert Acl(number="3000").is_empty() is True

    def test_only_deny_any(self) -> None:
        acl = Acl(number="3000")
        acl.rules.append(AclRule(seq=5, action="deny", protocol="ip"))
        assert acl.only_deny_any() is True

    def test_deny_any_plus_permit_not_only(self) -> None:
        acl = Acl(number="3000")
        acl.rules.append(AclRule(seq=5, action="deny", protocol="ip"))
        acl.rules.append(AclRule(seq=10, action="permit", protocol="ip"))
        assert acl.only_deny_any() is False
