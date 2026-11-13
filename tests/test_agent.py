"""Agent 层测试：提议、解析、对抗评测的完整链路。

## 这组测试的关键约束

**测的是机制，不是模型。** 用 FakeClient 回放固定响应，因此测出来的
任何失败都是代码问题，不是「模型这次答得不好」。

## 一个必须单独测的点：提示词不能泄漏规则

如果提示词里出现 "OSPF-001" 或「本工具会检查以下 12 项」，模型产出的
假设就会向规则覆盖范围收敛，对抗评测立刻退化成「模型能不能读懂规则清单」。
这条约束靠人记住是不可靠的，所以写成断言。
"""

from __future__ import annotations

import pytest

from netguard.agent.adversarial import adversarial_eval
from netguard.agent.llm import ChatResponse, FakeClient, LLMError, ToolCall
from netguard.agent.propose import (
    KINDS,
    KIND_TO_RULE,
    Proposal,
    build_prompt,
    parse_proposals,
    propose_defects,
    proposals_to_specs,
)

CASE01 = open("corpus/case01_core_switch.txt", encoding="utf-8").read()


def _fake(content: str) -> FakeClient:
    return FakeClient([ChatResponse(content=content)])


# ===========================================================================
# 1. 提示词约束
# ===========================================================================


class TestPromptIsolation:
    def test_prompt_has_no_rule_ids(self) -> None:
        """提示词里不能出现任何规则 ID —— 泄漏即失效。"""
        prompt = build_prompt(CASE01)
        blob = "\n".join(m["content"] for m in prompt)
        for rid in KIND_TO_RULE.values():
            assert rid not in blob, f"提示词泄漏了规则 ID {rid}"

    def test_prompt_has_no_rule_count(self) -> None:
        """不能告诉模型「有 12 条规则」——这会暴露评测口径。"""
        blob = "\n".join(m["content"] for m in build_prompt(CASE01))
        assert "12 条规则" not in blob
        assert "规则库" not in blob

    def test_prompt_contains_config_with_line_numbers(self) -> None:
        blob = "\n".join(m["content"] for m in build_prompt(CASE01))
        assert "sysname SW-Core-01" in blob
        # 行号右对齐，宽度随总行数而定（40 行 → 宽度 2）
        lines = CASE01.splitlines()
        width = len(str(len(lines)))
        assert f"{1:>{width}} | {lines[0]}" in blob
        # 最后一行也必须带行号，否则模型定位末尾时行号对不上
        assert f"{len(lines):>{width}} | {lines[-1]}" in blob

    def test_prompt_lists_all_kinds(self) -> None:
        blob = "\n".join(m["content"] for m in build_prompt(CASE01))
        for kind in KINDS:
            assert kind in blob


# ===========================================================================
# 2. 输出解析
# ===========================================================================


class TestParseProposals:
    def test_clean_json(self) -> None:
        raw = '[{"line_no": 5, "kind": "ip_conflict", "note": "重叠"}]'
        out = parse_proposals(raw)
        assert len(out) == 1
        assert out[0].line_no == 5
        assert out[0].kind == "ip_conflict"

    def test_json_wrapped_in_prose(self) -> None:
        """小模型常在 JSON 前后加解释，不该因此判失败。"""
        raw = '好的，我发现了问题：\n[{"line_no": 5, "kind": "ip_conflict", "note": "重叠"}]\n以上。'
        assert len(parse_proposals(raw)) == 1

    def test_json_in_code_fence(self) -> None:
        raw = '```json\n[{"line_no": 5, "kind": "telnet_open", "note": "x"}]\n```'
        assert len(parse_proposals(raw)) == 1

    def test_unknown_kind_dropped(self) -> None:
        """不认识的类别不能进评测——它无法被裁决。"""
        raw = '[{"line_no": 5, "kind": "i_dont_know", "note": "x"}]'
        assert parse_proposals(raw) == []

    def test_bad_line_no_dropped(self) -> None:
        raw = '[{"line_no": "abc", "kind": "ip_conflict", "note": "x"}]'
        assert parse_proposals(raw) == []

    def test_empty_array(self) -> None:
        assert parse_proposals("[]") == []

    def test_garbage_returns_empty(self) -> None:
        """解析不出来就返回空，不凭空造假设。"""
        assert parse_proposals("我觉得这台设备挺好的") == []
        assert parse_proposals("") == []

    def test_empty_array_not_treated_as_error(self) -> None:
        """空数组是合法回答（真的没问题），不是格式错误。"""
        proposals, err = propose_defects(_fake("[]"), CASE01)
        assert proposals == []
        # 空数组解析成功但无内容，会走「模型未提出假设」分支
        assert err is None or "未提出" not in (err or "")


# ===========================================================================
# 3. 映射
# ===========================================================================


class TestMapping:
    def test_every_kind_maps_to_a_rule(self) -> None:
        """KINDS 与 KIND_TO_RULE 必须一一对应，漏一个就会产生永远无法解释的假设。"""
        assert set(KINDS) == set(KIND_TO_RULE)

    def test_proposals_to_specs(self) -> None:
        specs, unmapped = proposals_to_specs(
            [Proposal(5, "ip_conflict", "x"), Proposal(1, "telnet_open", "y")]
        )
        assert len(specs) == 2
        assert specs[0].expect_rule == "IF-001"
        assert specs[1].expect_rule == "SEC-001"
        assert unmapped == []


# ===========================================================================
# 4. 对抗评测端到端
# ===========================================================================


class TestAdversarialEval:
    def test_all_hit(self) -> None:
        client = _fake(
            '[{"line_no": 5, "kind": "ip_conflict", "note": "重叠"},'
            ' {"line_no": 29, "kind": "acl_shadow", "note": "覆盖"},'
            ' {"line_no": 33, "kind": "telnet_open", "note": "开 telnet"}]'
        )
        r = adversarial_eval(client, CASE01, "case01")
        assert r.ok
        s = r.summary()
        assert s["valid_claims"] == 3
        assert s["true_positives"] == 3
        assert s["recall"] == 1.0

    def test_invalid_claim_not_counted_against_recall(self) -> None:
        """模型看错的假设不进分母——规则不为模型的错误买单。"""
        client = _fake(
            '[{"line_no": 5, "kind": "ip_conflict", "note": "真"},'
            ' {"line_no": 1, "kind": "acl_empty", "note": "假：case01 的 ACL 3000 有 permit"}]'
        )
        r = adversarial_eval(client, CASE01, "case01")
        assert r.ok
        s = r.summary()
        assert s["claims"] == 1 or s["claims"] == 2
        assert s["recall"] == 1.0
        assert s["invalid_claims"] >= 1

    def test_model_error_degrades_not_raises(self) -> None:
        class Boom:
            def chat(self, messages, tools=None):
                raise LLMError("连接失败")

        r = adversarial_eval(Boom(), CASE01, "case01")
        assert not r.ok
        assert "连接失败" in (r.error or "")

    def test_unparseable_output_retries_then_degrades(self) -> None:
        client = FakeClient([ChatResponse(content="我不会"), ChatResponse(content="还是不")])
        r = adversarial_eval(client, CASE01, "case01")
        assert not r.ok
        assert r.error
        # 至少调了两次：原始 + 重试
        assert len(client.calls) >= 2

    def test_retry_recovers(self) -> None:
        """第一次格式错，第二次纠正——应当成功。"""
        client = FakeClient(
            [
                ChatResponse(content="我觉得有 ip_conflict"),
                ChatResponse(content='[{"line_no": 5, "kind": "ip_conflict", "note": "x"}]'),
            ]
        )
        r = adversarial_eval(client, CASE01, "case01")
        assert r.ok
        assert r.summary()["true_positives"] == 1

    def test_unexplained_reported(self) -> None:
        """规则报出但没有假设指向的，要列出来供人工判定误报/漏标。"""
        client = _fake('[{"line_no": 5, "kind": "ip_conflict", "note": "x"}]')
        r = adversarial_eval(client, CASE01, "case01")
        assert r.ok
        assert "ACL-001" in r.report.unexplained


# ===========================================================================
# 5. LLM 客户端
# ===========================================================================


class TestToolCallSignature:
    def test_key_order_does_not_matter(self) -> None:
        """同一次调用换个键序不是新进展，否则重复检测失效。"""
        a = ToolCall("run_rule", {"device_id": "d", "rule_id": "IF-001"})
        b = ToolCall("run_rule", {"rule_id": "IF-001", "device_id": "d"})
        assert a.signature() == b.signature()

    def test_different_args_differ(self) -> None:
        a = ToolCall("run_rule", {"rule_id": "IF-001"})
        b = ToolCall("run_rule", {"rule_id": "ACL-001"})
        assert a.signature() != b.signature()


class TestFakeClient:
    def test_exhausted_returns_empty(self) -> None:
        """脚本用完返回空响应，用于测「模型空转」降级。"""
        c = FakeClient([])
        r = c.chat([])
        assert not r.has_tool_calls
        assert r.content == ""
