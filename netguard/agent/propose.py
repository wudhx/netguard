"""缺陷假设提出器：让模型在不掌握规则知识的前提下，独立判断「哪里配错了」。

## 为什么提示词里绝不能出现规则 ID 或规则清单

一旦模型知道「有 OSPF-001 这条规则、它判的是跨区域 IP」，它产出的假设就
必然向规则覆盖范围收敛——于是评测测的是「模型能不能读懂规则清单」，
不是「规则能不能抓住真实缺陷」。这是整个对抗评测能否成立的前提。

因此本模块的提示词只描述**设备该做什么**，不描述**本工具查什么**。
模型看到的是运维常识，不是测试大纲。

## 为什么要求「缺陷只落在可判定的范围内」

无限定的「找问题」会产出大量本工具不负责的东西（比如「这台设备没配 NTP」）。
这些不是假假设，是不相关假设，会把 `invalid_claims` 抬高到失去意义。

所以提示词里给出**输入边界**（单设备、只看这份配置文本、只关心会导致
转发或管理面异常的问题），但不给规则清单。边界是「什么问题算问题」，
清单是「本工具查什么」——前者是领域共识，后者是答案泄漏。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..core.eval_inject import InjectionSpec
from .llm import LLMError, ToolCall

__all__ = [
    "Proposal",
    "build_prompt",
    "parse_proposals",
    "propose_defects",
]


# 模型可以声明的缺陷类别。与 `core/eval_inject.py` 的 `_LOOKUPS` 一一对应。
#
# 为什么用枚举而不是自由文本：
# 自由文本无法被机械裁决，评测会退化成人工评审。这个列表是「模型说的」与
# 「代码能验的」之间的契约——模型只能提这些类别，也只能被这些类别核对。
#
# 注意：这个列表**不暴露规则 ID**。类别名描述的是配置现象，不是规则编号。
KINDS = {
    "ip_conflict": "同一设备上两个接口的 IP 网段重叠（互相冲突）",
    "acl_shadow": "ACL 中前面的 deny 规则把后面的 permit 完全挡住了",
    "acl_empty": "被接口引用的 ACL 里没有任何 permit 规则（会把流量全挡住）",
    "acl_bad_wildcard": "ACL 的反掩码不是连续的（写法非法，实际匹配范围不可预期）",
    "ospf_ip_multi_area": "同一个接口的 IP 被多个 OSPF 区域的 network 声明覆盖",
    "ospf_area_uncovred": "接口配置了 OSPF 使能，但它所在区域的 network 没有覆盖它",
    "ospf_network_dangling": "OSPF 的 network 声明的网段里，本机没有任何接口",
    "telnet_open": "设备启用了 Telnet 远程登录",
}


_SYSTEM = """你是一名资深网络运维工程师，正在审阅一台华为 VRP 设备的配置。
你的任务是：仅凭运维常识，找出这份配置里**看起来配错了**的地方。

约束：
1. 只看这一份配置。不要假设你没看到的东西是什么样。
2. 只关心会导致**转发异常**或**管理面暴露**的问题。
3. 不确定的不要提——宁可少提，不可乱提。
4. 不要评价风格、命名、注释、顺序美观。
5. 每条问题必须能落到具体一处配置上。

你只能报告以下几类问题（用英文类别名）：
{kinds}

按 JSON 数组输出，不要输出别的内容。每项字段：
- line_no: 问题所在的配置行号（整数，从 1 开始，指向最相关的那一行）
- kind: 上面列表里的英文类别名
- note: 一句话说明为什么这算问题（中文，30 字以内）

输出示例：
[{{"line_no": 12, "kind": "ip_conflict", "note": "Vlanif10 与 Vlanif20 地址重叠"}}]

若确实找不到问题，输出空数组 []。"""


@dataclass
class Proposal:
    """模型提出的一条缺陷假设（未裁决）。"""

    line_no: int
    kind: str
    note: str

    def to_spec(self, expect_rule: str) -> InjectionSpec:
        return InjectionSpec(
            line_no=self.line_no, kind=self.kind, expect_rule=expect_rule, note=self.note
        )


#: kind → 负责这条缺陷的规则 ID。
#:
#: 这张表只用于把「模型提的假设」翻译成「该由哪条规则负责判定」。
#: 它不出现在提示词里——模型不知道它的存在。
#:
#: 若某类假设对应的规则不存在（模型提了一个本工具不查的问题），
#: 映射取空串，评测时会被记为「无法核对」而非「规则漏报」。
KIND_TO_RULE = {
    "ip_conflict": "IF-001",
    "acl_shadow": "ACL-001",
    "acl_empty": "ACL-004",
    "acl_bad_wildcard": "ACL-002",
    "ospf_ip_multi_area": "OSPF-001",
    "ospf_area_uncovred": "OSPF-004",
    "ospf_network_dangling": "OSPF-002",
    "telnet_open": "SEC-001",
}


def build_prompt(config_text: str) -> list[dict]:
    """构造提议用的消息序列。

    ## 只放配置，不放任何规则信息

    见模块 docstring。这条约束不因为「模型表现不好」而放宽——放宽了，
    评测的独立性就没了，这个数字也就不值钱了。
    """
    kinds_text = "\n".join(f"- {k}：{v}" for k, v in KINDS.items())
    return [
        {"role": "system", "content": _SYSTEM.format(kinds=kinds_text)},
        {
            "role": "user",
            "content": f"以下是设备配置（行号已标注在左侧）：\n\n{_number_lines(config_text)}",
        },
    ]


def _number_lines(text: str) -> str:
    """给配置加行号，便于模型定位。

    模型报的行号必须能被映射回原文，因此这里用与原文完全一致的 1-based
    编号，不做任何裁剪——裁剪会让行号对不上，所有假设作废。
    """
    lines = text.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{idx:>{width}} | {line}" for idx, line in enumerate(lines, 1))


_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.S)


def parse_proposals(raw: str) -> list[Proposal]:
    """从模型输出中抽出假设列表。

    ## 为什么要容忍前后废话

    小模型（7—8B）常常在 JSON 前后加解释或 markdown 代码块。strict 解析
    会让「模型其实答对了但格式不干净」被判为失败，白白浪费一次调用。
    因此先尝试直接解析，失败则抓第一个 JSON 数组再解析。

    但这不等于宽容到什么都收：解析不出来就返回空列表，由调用方决定
    （通常是记一次降级），而不是凭空造假设。
    """
    text = raw.strip()
    if not text:
        return []

    candidates = [text]
    m = _JSON_ARRAY_RE.search(text)
    if m:
        candidates.append(m.group(0))

    for cand in candidates:
        try:
            data = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, list):
            continue
        out: list[Proposal] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                line_no = int(item.get("line_no"))
            except (TypeError, ValueError):
                continue
            kind = str(item.get("kind", "")).strip()
            if kind not in KINDS:
                continue
            out.append(Proposal(line_no=line_no, kind=kind, note=str(item.get("note", ""))[:80]))
        return out

    return []


def propose_defects(
    client,
    config_text: str,
    *,
    max_retry: int = 1,
) -> tuple[list[Proposal], str | None]:
    """让模型提一批缺陷假设。返回 `(假设列表, 错误信息)`。

    ## 为什么返回错误而不是抛异常

    提议失败不得中断评测——评测的产出是「规则召回率」这个数字，
    提议失败只意味着这一份配置没有对抗样本，应该跳过并记录，
    而不是让整批数字作废。

    ## 为什么重试是单独一次而不是循环

    一次重试覆盖「偶发格式错误」，两次以上覆盖的是「模型根本不会做这件事」。
    后者重试再多也是浪费，应该让它降级。

    注意此处**不传 tools**：提议走的是纯文本 JSON 输出，不依赖模型的
    tool calling 能力。这样即便模型不支持 tools，提议功能依然可用——
    而 agent 的承重性不因此打折：它承的是「提出假设」这件事，不是「调工具」。
    """
    messages = build_prompt(config_text)

    last_error: str | None = None
    for attempt in range(max_retry + 1):
        try:
            resp = client.chat(messages, tools=None)
        except LLMError as exc:
            last_error = f"模型调用失败：{exc}"
            break

        proposals = parse_proposals(resp.content)
        if proposals:
            return proposals, None

        if resp.content.strip():
            last_error = f"第 {attempt + 1} 次输出无法解析为假设列表"
            messages = messages + [
                {"role": "assistant", "content": resp.content},
                {"role": "user", "content": "格式不对。请只输出 JSON 数组，不要任何其他文字。"},
            ]
        else:
            last_error = "模型返回空内容"
            break

    return [], last_error


def proposals_to_specs(proposals: list[Proposal]) -> tuple[list[InjectionSpec], list[Proposal]]:
    """把假设翻译成可裁决的 spec。

    返回 `(可裁决的 spec, 无法映射到任何规则的假设)`。

    无法映射的假设单独返回而不是丢弃：它说明模型提了一个本工具不负责的
    问题（或提了一个本工具该查但还没实现的规则）。前者过滤掉，后者是
    **规则库的缺口线索**，要留给人看。
    """
    specs: list[InjectionSpec] = []
    unmapped: list[Proposal] = []
    for p in proposals:
        rule_id = KIND_TO_RULE.get(p.kind, "")
        if not rule_id:
            unmapped.append(p)
            continue
        specs.append(p.to_spec(rule_id))
    return specs, unmapped
