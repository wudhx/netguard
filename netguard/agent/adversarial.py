"""对抗式缺陷评测：模型提议 → 代码裁决 → 规则判定。

这是 M6，也是本项目里 agent 唯一不可替代的地方。

## 一次性说清它为什么承重

问：「删掉 agent 层，系统会丧失什么能力？」

答：**丧失「规则库以外的问题」的发现能力，以及「规则库漏报率」这个数字。**

具体展开：

1. 规则库能报什么，在写规则的那一刻就定死了。它不会自己发现「我漏了
   一类问题」。
2. 要发现漏报，必须有**独立于规则库的缺陷来源**。人做来源不可行——
   人想到的缺陷就是已经写成规则的那批。
3. 因此，模型是唯一能提供「规则库没想到的缺陷」的来源。删掉它，
   漏报率就永远是未知数。

这不是「输出质量下降」，是「一项能力归零」。

## 与「补丁生成」的区别

补丁生成的问题在于：它的产物（补丁）必须由人判断采纳，所以 agent 的
必要性会被「我自己也能改」削弱。

而对抗评测的产物是一个**数字**（漏报率）。这个数字由代码算，模型无法
自述；人也没法自己算——除非人先把缺陷想全，而那正是做不到的事。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.eval_inject import EvalReport, InjectionSpec, evaluate
from ..core.parser import parse
from .llm import LLMError
from .propose import Proposal, propose_defects, proposals_to_specs

__all__ = [
    "AdversarialResult",
    "adversarial_eval",
]


@dataclass
class AdversarialResult:
    """一次对抗评测的完整记录。"""

    device_id: str
    proposals: list[Proposal] = field(default_factory=list)
    specs: list[InjectionSpec] = field(default_factory=list)
    unmapped: list[Proposal] = field(default_factory=list)
    report: EvalReport | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.report is not None

    def summary(self) -> dict:
        if self.report is None:
            return {"device_id": self.device_id, "error": self.error or "未知错误"}
        base = self.report.summary()
        base["device_id"] = self.device_id
        base["proposals"] = len(self.proposals)
        base["unmapped"] = len(self.unmapped)
        return base


def adversarial_eval(
    client,
    config_text: str,
    device_id: str = "unknown",
) -> AdversarialResult:
    """对一份配置执行对抗评测。

    ## 全链路

        配置文本
           ↓ 模型读（不知道规则清单）
        缺陷假设 proposals
           ↓ 映射（KIND_TO_RULE，模型不知道这张表）
        InjectionSpec
           ↓ 代码裁决（lookup）
        假设是否成立
           ↓ 规则全量扫描
        规则报出集合
           ↓ 比对
        召回率 / 假设有效率 / unexplained

    ## 提议失败时的行为

    返回带 `error` 的结果，不抛异常。理由：这是评测，不是巡检。
    某一份配置提议失败只影响这一份的样本量，不应让整批评测中断。
    """
    result = AdversarialResult(device_id=device_id)

    proposals, err = propose_defects(client, config_text)
    result.proposals = proposals

    if err is not None and not proposals:
        result.error = err
        return result

    specs, unmapped = proposals_to_specs(proposals)
    result.specs = specs
    result.unmapped = unmapped

    if not specs:
        result.error = "模型未提出任何可裁决的缺陷假设"
        return result

    cfg = parse(config_text, device_id=device_id)
    result.report = evaluate(cfg, specs, full_sweep=True)
    return result
