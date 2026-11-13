"""缺陷注入评测的单元测试。

## 这组测试在测什么

不是测「规则会不会报」，而是测**评测机制本身是否可信**：

1. 裁决器判得准不准（一条假设是否真的成立）
2. 召回率的分母对不对（提议方看错的假设不能算规则的账）
3. 过滤是否真的被绕开（`full_sweep` 默认生效）

第 2 点最容易被写错。如果分母包含「不成立的假设」，那么模型提得越离谱、
被驳掉的越多，召回率的分母越大、反而越好看——这个指标就废了。
"""

from __future__ import annotations

import pytest

from netguard.core.engine import run_all_rules
from netguard.core.eval_inject import (
    InjectionSpec,
    aggregate,
    evaluate,
    lookup,
)
from netguard.core.parser import parse, parse_file

# ===========================================================================
# 1. 裁决器
# ===========================================================================


class TestLookup:
    def test_ip_conflict_true(self) -> None:
        cfg = parse(
            "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
            "interface Vlanif20\n ip address 10.0.0.2 255.255.255.0\n"
        )
        r = lookup(cfg, InjectionSpec(1, "ip_conflict", "IF-001"))
        assert r.ok

    def test_ip_conflict_false(self) -> None:
        cfg = parse(
            "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
            "interface Vlanif20\n ip address 10.1.0.1 255.255.255.0\n"
        )
        assert not lookup(cfg, InjectionSpec(1, "ip_conflict", "IF-001")).ok

    def test_acl_shadow_true(self) -> None:
        cfg = parse(
            "acl number 3000\n"
            " rule 5 deny ip source 10.0.0.0 0.0.0.255\n"
            " rule 10 permit ip source 10.0.0.5 0.0.0.0\n"
        )
        assert lookup(cfg, InjectionSpec(1, "acl_shadow", "ACL-001")).ok

    def test_acl_shadow_false_when_deny_narrower(self) -> None:
        """deny 只挡 /32，permit 放开整个网段——permit 仍能生效，不算覆盖。"""
        cfg = parse(
            "acl number 3000\n"
            " rule 5 deny ip source 10.0.0.5 0.0.0.0\n"
            " rule 10 permit ip source 10.0.0.0 0.0.0.255\n"
        )
        assert not lookup(cfg, InjectionSpec(1, "acl_shadow", "ACL-001")).ok

    def test_acl_empty_true(self) -> None:
        cfg = parse("acl number 3000\ninterface GigabitEthernet0/0/1\n traffic-filter inbound acl 3000\n")
        assert lookup(cfg, InjectionSpec(1, "acl_empty", "ACL-004")).ok

    def test_acl_empty_false_when_not_bound(self) -> None:
        """空 ACL 没被引用，不构成风险。"""
        cfg = parse("acl number 3000\n")
        assert not lookup(cfg, InjectionSpec(1, "acl_empty", "ACL-004")).ok

    def test_bad_wildcard_true(self) -> None:
        cfg = parse("acl number 3000\n rule 5 permit ip source 10.0.0.0 0.0.255.0\n")
        assert lookup(cfg, InjectionSpec(1, "acl_bad_wildcard", "ACL-002")).ok

    def test_telnet_open_true(self) -> None:
        assert lookup(parse("telnet server enable\n"), InjectionSpec(1, "telnet_open", "SEC-001")).ok

    def test_telnet_open_false_after_undo(self) -> None:
        cfg = parse("telnet server enable\nundo telnet server enable\n")
        assert not lookup(cfg, InjectionSpec(1, "telnet_open", "SEC-001")).ok

    def test_ospf_network_dangling_true(self) -> None:
        cfg = parse(
            "ospf 1 router-id 1.1.1.1\n area 0.0.0.0\n  network 192.168.99.0 0.0.0.255\n"
        )
        assert lookup(cfg, InjectionSpec(1, "ospf_network_dangling", "OSPF-002")).ok

    def test_unknown_kind_rejected(self) -> None:
        """不认识的缺陷类别一律不成立——不可核对的假设不能算数。"""
        r = lookup(parse(""), InjectionSpec(1, "made_up_kind", "X-001"))
        assert not r.ok
        assert "无法核对" in r.detail


# ===========================================================================
# 2. 召回率的分母纪律
# ===========================================================================


class TestRecallDenominator:
    def test_invalid_claims_not_counted_against_rules(self) -> None:
        """提议方看错的假设不能压低规则召回率。"""
        cfg = parse(
            "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
            "interface Vlanif20\n ip address 10.0.0.2 255.255.255.0\n"
        )
        specs = [
            InjectionSpec(1, "ip_conflict", "IF-001"),      # 成立，会被抓到
            InjectionSpec(1, "telnet_open", "SEC-001"),     # 不成立（没开 telnet）
        ]
        rep = evaluate(cfg, specs)
        s = rep.summary()
        assert s["claims"] == 2
        assert s["valid_claims"] == 1
        assert s["invalid_claims"] == 1
        # 召回 = 1/1，不是 1/2
        assert s["recall"] == 1.0

    def test_false_negative_detected(self) -> None:
        """真缺陷存在但规则没报——这是漏报。"""
        cfg = parse("interface Vlanif10\n")
        specs = [InjectionSpec(1, "ip_conflict", "IF-001")]
        rep = evaluate(cfg, specs)
        # 只有一个接口，不构成冲突 → 假设不成立，不是漏报
        assert rep.records[0].is_invalid_claim
        assert not rep.records[0].is_false_negative

    def test_must_require_expected_rule(self) -> None:
        """只要求「有规则报了」会让笼统假设靠无关 finding 蒙混过关。"""
        cfg = parse(
            "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
            "interface Vlanif20\n ip address 10.0.0.2 255.255.255.0\n"
        )
        # 真值说这是 OSPF 问题，实际是 IF-001 问题 → 应判漏报
        specs = [InjectionSpec(1, "ip_conflict", "OSPF-001")]
        rep = evaluate(cfg, specs)
        assert rep.records[0].lookup.ok
        assert not rep.records[0].hit
        assert rep.records[0].is_false_negative

    def test_empty_specs_recall_zero(self) -> None:
        assert evaluate(parse(""), []).summary()["recall"] == 0.0


# ===========================================================================
# 3. 全量扫描：评测不受角色/能力过滤影响
# ===========================================================================


class TestFullSweep:
    def test_eval_runs_all_rules_despite_role_filter(self) -> None:
        """专项语料常被判成 access，若评测走过滤会漏测 OSPF 规则。"""
        cfg = parse_file("corpus/case04_ospf_errors.txt")
        filtered = run_all_rules(cfg)
        assert "OSPF-004" in filtered.rules_run or "OSPF-004" in filtered.skipped

        specs = [InjectionSpec(12, "ospf_area_uncovred", "OSPF-004")]
        rep = evaluate(cfg, specs)
        # 全量扫描下 OSPF-004 一定被跑，因此假设成立且命中
        assert rep.records[0].lookup.ok
        assert rep.records[0].hit

    def test_unexplained_lists_unaccounted_findings(self) -> None:
        cfg = parse_file("corpus/case01_core_switch.txt")
        specs = [InjectionSpec(5, "ip_conflict", "IF-001")]
        rep = evaluate(cfg, specs)
        # case01 还报了 ACL-001/ACL-003/OSPF-001/OSPF-003/SEC-001
        assert "ACL-001" in rep.unexplained
        assert "IF-001" not in rep.unexplained


# ===========================================================================
# 4. 聚合
# ===========================================================================


class TestAggregate:
    def test_recall_uses_claim_denominator_not_device(self) -> None:
        """按配置平均会让假设少的配置权重过大，必须按假设数做分母。"""
        cfg_a = parse(
            "interface Vlanif10\n ip address 10.0.0.1 255.255.255.0\n"
            "interface Vlanif20\n ip address 10.0.0.2 255.255.255.0\n"
        )
        cfg_b = parse("telnet server enable\n")

        rep_a = evaluate(cfg_a, [InjectionSpec(1, "ip_conflict", "IF-001")])
        rep_b = evaluate(
            cfg_b,
            [
                InjectionSpec(1, "telnet_open", "SEC-001"),
                InjectionSpec(1, "ip_conflict", "IF-001"),   # 不成立
                InjectionSpec(1, "acl_shadow", "ACL-001"),   # 不成立
            ],
        )
        agg = aggregate([rep_a, rep_b])
        assert agg["devices"] == 2
        assert agg["claims"] == 4
        assert agg["valid_claims"] == 2
        assert agg["true_positives"] == 2
        assert agg["recall"] == 1.0

    def test_aggregate_empty(self) -> None:
        agg = aggregate([])
        assert agg["devices"] == 0
        assert agg["recall"] == 0.0


# ===========================================================================
# 5. 真实语料基线
# ===========================================================================


CORPUS_TRUTH = {
    "case01_core_switch.txt": [
        InjectionSpec(5, "ip_conflict", "IF-001", "Vlanif10/20 网段重叠"),
        InjectionSpec(29, "acl_shadow", "ACL-001", "rule 5 deny 覆盖 rule 10 permit"),
        InjectionSpec(1, "ospf_ip_multi_area", "OSPF-001", "Vlanif10 IP 落入两个区域"),
    ],
    "case04_ospf_errors.txt": [
        InjectionSpec(12, "ospf_area_uncovred", "OSPF-004", "接口未被 network 覆盖"),
        InjectionSpec(1, "ospf_network_dangling", "OSPF-002", "network 无接口覆盖"),
    ],
    "case05_acl_errors.txt": [
        InjectionSpec(17, "acl_bad_wildcard", "ACL-002", "反掩码非连续"),
        InjectionSpec(1, "acl_empty", "ACL-004", "空 ACL 被引用"),
    ],
    "case06_interface_errors.txt": [
        InjectionSpec(1, "ip_conflict", "IF-001", "Vlanif10/30 网段重叠"),
    ],
}


class TestCorpusBaseline:
    @pytest.mark.parametrize("filename", sorted(CORPUS_TRUTH))
    def test_recall_100_on_annotated_corpus(self, filename: str) -> None:
        """人工标注语料上，规则召回率必须 100%。

        这不是炫耀指标，是回归护栏：任何一条规则被改坏、或解析器漏解析
        导致规则失效，这条断言会立刻红。基线下降必须能解释原因。
        """
        cfg = parse_file(f"corpus/{filename}")
        rep = evaluate(cfg, CORPUS_TRUTH[filename])
        s = rep.summary()
        assert s["valid_claims"] == len(CORPUS_TRUTH[filename]), (
            f"{filename}: 有假设未被裁决为成立，标注或裁决器有问题。详情："
            f"{[(r.spec.kind, r.lookup.detail) for r in rep.records if not r.lookup.ok]}"
        )
        assert s["recall"] == 1.0, (
            f"{filename}: 漏报 {[(r.spec.kind, r.spec.expect_rule) for r in rep.false_negatives]}"
        )

    def test_aggregate_over_all_annotated(self) -> None:
        reports = [
            evaluate(parse_file(f"corpus/{name}"), specs)
            for name, specs in CORPUS_TRUTH.items()
        ]
        agg = aggregate(reports)
        assert agg["recall"] == 1.0
        assert agg["invalid_claims"] == 0
        # 3 + 2 + 2 + 1 = 8。这个数字随语料扩增而变，改它必须同时加语料。
        assert agg["true_positives"] == sum(len(s) for s in CORPUS_TRUTH.values())
