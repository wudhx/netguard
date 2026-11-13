# NetGuard 架构补充规格：补丁草案生成（Patch Draft）

> 性质：`architecture.md`（V4.0）的**增量补充规格**，定义一项新增能力。
> 日期：2026-11-13
> 关系：本文档只定义「补丁草案生成」这一项能力，以及它需要对 V4.0 造成的修改。V4.0 其他部分不变。

---

## 0. 使用说明（给接收方 AI）

1. 本文档要**合并进 `architecture.md`**，产出 V5.0 单一自包含版本。合并方式见 §11 的逐节修改清单。
2. §12 列出了**禁止事项**，这些是设计边界，不要"顺手优化"掉。
3. 遇到与 V4.0 冲突的地方，以本文档为准；本文档未涉及的，以 V4.0 为准。
4. 不确定的地方列成问题回问，不要自行扩大范围。

---

## 1. 要解决的问题

当前 V4.0 存在一个结构性弱点：**Agent 层可以被删除而不影响系统的核心可用性。**

V4.0 §10.2 的 MVP 线自己写明「不装 Ollama 也能输出 12 条规则的完整风险列表」。这句话诚实，但同时暴露了：**判定这一层完全不依赖模型。**

逐项检查 V4.0 §7.5 的五个承重机制（M1—M5）：

| 机制 | 没有模型会怎样 | 真正贡献 |
|---|---|---|
| M1 规则选择 | 全跑 5—9 条候选，耗时仍在毫秒级，结果完全一致 | 接近零（V4.0 §7.2 已自行承认） |
| M2 线索追踪 | 机械跟随全部 `hint`，结论一致，只多几条噪声 | 判断「这条线索值不值得追」——弱 |
| M3 归因合并 | N 条 finding 平铺输出 | 把 N 条归并为 M 个根因——**唯一硬价值** |
| M4 多轮追问 | 无 | 交互便利，V4.0 已排除出 DoD |
| M5 报告自校验 | 无 | 它存在是因为 M3 让模型写了话，属 M3 的配套设施 |

**结论：只有 M3 是不可替代的，而 M3 属于「表达层」。** 于是整个 agent 层被定性为"翻译层"——有价值，但删掉后系统照样能用，只是输出退化成清单。

这直接导致 V4.0 §2 的 P2「Agent 必须承重」在面试中站不住：删掉 agent 层，系统并没有"丧失某项能力"，只是"降低输出质量"。

---

## 2. 根因：判定是确定性的，决策不是

| | 判定 | 决策 |
|---|---|---|
| 例子 | 这条 ACL 有没有顺序风险 | 这条 ACL 该怎么改、插在第几条 |
| 正解数量 | 唯一（对/错） | 多个（多种改法都可行） |
| 能否写成算法 | 能——规则引擎就是干这个的 | **不能，需要权衡** |
| 需要模型 | 不需要 | **必须有** |

**核心判断：Agent 只有在「有多个正解、需要权衡」的任务上才不可替代。** 只要系统停留在"判定"，agent 就只能是翻译层。

本领域的这类任务只有一件：**修复方案的设计。** 因为它是组合问题，且目标函数（什么叫"最小风险改法"）无法形式化。

举例：规则报「ACL 3000 第 5 条 permit 被第 2 条 deny 覆盖」之后，需要决定——

- 把 permit 提到 deny 之前？还是把 deny 收窄到更精确的地址段？还是拆成两个 ACL？
- 若调整顺序，插在第几条？前面是否还有规则依赖当前顺序？
- 这条 ACL 同时挂在另外两个接口上，改一处是否影响其他业务？
- 改动后原本被挡住的流量会放通，是否产生新风险？

这些无法穷举，也无法写成 if-else。**这是模型的战场，不是规则的。**

---

## 3. 新增机制：生成 → 机械验证 → 修正 闭环

### 3.1 原则

**模型只负责"生成候选方案"，对错由确定性代码验证。** 这与 V4.0 P1「判定与表达分离」不冲突——模型不判定任何风险是否存在，只提出变更方案；方案是否有效，由规则引擎重新跑一遍来裁决。

### 3.2 数据流

```
巡检产出 findings（确定性）
        ↓
Agent 选定要修的 finding（仅 patchable 的）
        ↓
propose_patch(finding_key)  →  Patch{operations[], rationale, risk_notes}
        ↓
verify_patch(patch_id)
        ↓  把 operations 应用回配置文本
        ↓  重新 parse → 重跑全部 12 条规则
        ↓  比对 fixed / remaining / regressed
        ↓
  regressed 为空 且 目标 finding 全部消失 ?
     ├─ 是 → 标记 verified=True，交给 submit_findings
     └─ 否 → 把 detail 回填给模型，重新 propose_patch（最多 2 次）
             └─ 仍失败 → 该 finding 走降级：只保留文字建议，不带 patch
```

### 3.3 这条闭环为什么是关键

它把「agent 是否真的起作用」变成了**机器可判定的问题**：

- 补丁有效没有，不看模型怎么说，看**应用后规则还报不报**
- 有没有副作用，不看模型怎么写，看**有没有新增 finding**

这是 V4.0 中 M5 的升级：从「校验归因文字指向真实发现」（查表），升级为「校验补丁是否真的消除风险」（闭环执行）。**从查表变成执行-观测-修正，这才是 agent 该有的形态。**

---

## 4. 数据结构

```python
@dataclass
class Operation:
    """一条原子配置变更。"""
    kind: str                      # "add" | "remove" | "modify"
    section: str                   # "acl" | "ospf"
    target: str                    # "acl 3000" | "ospf 1 area 0.0.0.0"
    before: str | None             # 变更前的原文行（add 时为 None）
    after: str | None              # 变更后的文本行（remove 时为 None）
    line_no: int | None            # 锚定行；None 表示追加到该 section 末尾


@dataclass
class Patch:
    """一份补丁草案。只描述变更，不代表已被应用。"""
    patch_id: str
    device_id: str
    finding_keys: list[str]        # 本补丁声称修复的 finding，格式 "rule_id@location"
    operations: list[Operation]    # 有序
    rationale: str                 # 为什么这么改（模型生成）
    risk_notes: list[str]          # 副作用提示（模型生成）
    attempt: int = 1               # 第几次尝试
    verified: bool = False
    verify_result: "VerifyResult | None" = None


@dataclass
class VerifyResult:
    verdict: str                   # "success" | "partial" | "failed"
    fixed: list[str]               # 已消失的 finding_keys
    remaining: list[str]           # 仍存在的
    regressed: list[str]           # 新引入的（这是最危险的）
    detail: str                    # 给模型看的失败原因，可直接回填
```

**`regressed` 是这套机制里最重要的字段**——它回答"修复有没有引入新问题"。真实运维中二次故障大多来自变更本身。

---

## 5. 工具接口（新增 2 个，总数 10 → 12）

```python
@tool(
    name="propose_patch",
    description=(
        "针对一条可修补的风险，生成配置变更草案。只生成不应用。"
        "生成后必须调用 verify_patch 验证，验证不通过时依据 detail 重新生成。"
    ),
    params={
        "device_id":  ("string", "设备标识"),
        "finding_key": ("string", "要修复的风险键，格式 rule_id@location，"
                                  "必须来自 get_findings 且 patchable=True"),
    },
    returns="Patch: {patch_id, operations[], rationale, risk_notes, attempt}",
)
def propose_patch(ctx: RunContext, device_id: str, finding_key: str) -> Patch: ...


@tool(
    name="verify_patch",
    description=(
        "把补丁应用到配置文本副本，重新解析并重跑全部规则，"
        "返回 fixed / remaining / regressed 三个集合。不修改任何原始文件。"
    ),
    params={
        "device_id": ("string", "设备标识"),
        "patch_id":  ("string", "propose_patch 返回的补丁 ID"),
    },
    returns="VerifyResult: {verdict, fixed[], remaining[], regressed[], detail}",
)
def verify_patch(ctx: RunContext, device_id: str, patch_id: str) -> VerifyResult: ...
```

### 5.1 `Finding` 与规则元数据的配套改动

- `@rule(...)` 新增字段 `patchable: bool = False`
- `Finding` 新增字段 `patchable: bool`（由规则元数据带出）
- `get_findings` 的返回中必须包含 `patchable`，供模型判断哪些可修

**Phase 1 只有两条规则 `patchable=True`**，见 §9。

### 5.2 `submit_findings` 的结构变化

```python
groups = [
    {
        "title": "...",
        "reason": "...",
        "suggestion": "...",          # 文字建议，始终有
        "supported_by": [0],          # V4.0 已有
        "patch": {                    # 新增，可为 None
            "patch_id": "...",
            "operations": [...],
            "risk_notes": [...],
            "verified": True,
        },
    },
]
```

**硬约束：`patch` 只在 `verified=True` 时才允许出现在报告中。** 未通过验证的补丁整份丢弃，只保留 `suggestion` 文字。

---

## 6. Agent 流程与终止条件

在 V4.0 §7.4 的两层循环内，单轮巡检流程扩展为：

```
1. get_device_profile → list_rules → run_rule（若干）→ 得到 findings
2. 从 findings 中筛出 patchable=True 的，最多取 3 条（预算控制）
3. 对每条：propose_patch → verify_patch
   - success → 记录
   - partial/failed → 用 detail 重新 propose_patch，最多 2 次
   - 2 次仍失败 → 放弃该条，记录 skipped
4. verify_claims（V4.0 已有）
5. submit_findings（带 patch）
```

### 6.1 新增预算

| 预算 | 值 | 理由 |
|---|---|---|
| 单轮最多生成补丁数 | 3 | 防止在一条配置上无限修 |
| 单补丁最多尝试次数 | 2 | 两次仍不成就说明模型搞不定，止损 |
| 单轮最多 verify_patch 调用 | 8 | 含重试 |

### 6.2 新增终止/降级条件

| 条件 | 结果 |
|---|---|
| 补丁生成超预算 | 剩余 finding 只出文字建议，`degraded:patch_budget` |
| 补丁连续 2 次验证失败 | 该 finding 放弃补丁，记入 `skipped_patches`，报告注明"建议人工处理" |
| `propose_patch` 返回格式非法 | pydantic 校验失败，回填错误重试 1 次，仍失败则放弃 |

**硬要求：补丁功能完全失败时，不影响巡检报告的正常产出。** 补丁是增强项，不是依赖项。

---

## 7. 机械验证算法（实现要点）

### 7.1 应用补丁

```
new_lines = copy(original_lines)
按 line_no 从大到小排序 operations     # ★ 必须倒序，否则行号漂移
逐条应用：
  add    → 在 line_no 之后插入 after
  remove → 删除 line_no 对应行
  modify → 用 after 替换 line_no 对应行
line_no 为 None 的 add → 追加到对应 section 末尾
```

**行号必须倒序应用，这是最容易写错的地方。** 正序应用会导致后续行号全部偏移，补丁打到错误的位置，而验证阶段又会因为"规则确实不报了"给出错误的 success。

### 7.2 重新解析与判定

```
new_cfg = parse(new_lines)              # 必须用同一个 parser，不得走捷径
new_findings = run_all_rules(new_cfg)   # 全部 12 条，不是只跑目标规则
```

**必须跑全部规则，不能只跑目标规则。** 只跑目标规则会完全漏掉 regressed——改 A 引入 B 的情况正是补丁最危险的地方。

### 7.3 集合比对

finding 的**身份键统一用 `(rule_id, location)`**，不要用 message（message 可能随上下文变化，会导致误判为新发现）：

```python
key = f"{f.rule_id}@{f.location}"
old_keys = {key(f) for f in old_findings}
new_keys = {key(f) for f in new_findings}

fixed     = old_keys - new_keys
remaining = old_keys & new_keys
regressed = new_keys - old_keys
```

判级：

| verdict | 条件 |
|---|---|
| `success` | 目标 finding_keys ⊆ fixed **且** regressed 为空 |
| `partial` | 目标部分消失，regressed 为空 |
| `failed` | regressed 非空（无论目标是否消失） |

**regressed 非空一律判 failed，即使目标风险消失了。** 引入新问题比留着旧问题更糟。

### 7.4 detail 的写法（给模型看）

失败时必须给出可操作的信息，而不是笼统的"失败"：

```
"补丁未通过：目标风险 ACL-001@acl 3000 rule 5 仍存在（remaining），
 且引入新风险 ACL-002@acl 3000 rule 5（regressed）。
 失败原因推测：新增的 rule 6 通配符不连续。"
```

模型据此重试。

---

## 8. 指标定义（新增三个）

| 指标 | 定义 | 确定性 | 目标 |
|---|---|---|---|
| **补丁有效率** | verdict=success 的补丁数 / 尝试生成的补丁总数（含未采用的重试） | 完全确定 | ≥ 0.70 |
| **回归率** | 产生 regressed 非空的补丁数 / 尝试生成的补丁总数 | 完全确定 | ≤ 0.10 |
| **补丁覆盖率** | 生成补丁的 patchable finding 数 / 全部 patchable finding 数 | 完全确定 | ≥ 0.80 |

### 8.1 为什么要单独设"覆盖率"

补丁有效率存在被"挑软柿子"刷高的风险——模型只对最简单的 finding 生成补丁，有效率自然好看。

**有效率与覆盖率必须同时报，单看任何一个都可以被操纵。**

### 8.2 分母纪律

分母是**尝试生成的补丁总数**，包含验证失败后重试的那几次。只统计"最终采纳的"会严重虚高。

### 8.3 报数示例

```
正确：「32 条可修补风险，生成补丁 28 条（覆盖率 0.88），
      其中一次通过 20 条（有效率 0.71），引入新风险 2 条（回归率 0.07）」
```

---

## 9. 范围限制：只做两条规则

**Phase 1 只有以下两条规则 `patchable=True`：**

| 规则 | 补丁形态 |
|---|---|
| `ACL-001` 前置 deny 覆盖后置 permit | 调整 rule 顺序，或收窄 deny 的地址范围 |
| `OSPF-004` 接口参与 OSPF 但未被 network 覆盖 | 在对应 `area` 下补一条 `network` 声明 |

其余 10 条规则**不生成补丁**，只输出文字建议。

**理由**：

1. 这两类占了真实配置故障的大头，且补丁形态清楚、可验证
2. 对 12 条规则全覆盖会让工作量翻倍，违反 V4.0 P7「范围守死」
3. 补丁能力的作用是**证明 agent 可以承重**，不是做一个完整的配置修复工具。两条足以证明机制成立

---

## 10. 安全与边界约束

| # | 约束 | 说明 |
|---|---|---|
| 1 | **补丁永不自动应用** | 只输出 diff，最终决定权在人。这是 V4.0 §12.2 的约束 1，Phase 1 起就必须成立 |
| 2 | **不修改原始配置文件** | 验证在内存副本上进行，原始 `.cfg` 只读 |
| 3 | **只承诺文本层有效** | 明确声明：验证的是"配置文本不再触发规则"，不承诺设备实际转发效果。该声明必须出现在报告和 README |
| 4 | **补丁失败不阻塞主流程** | 补丁是增强项，任何补丁异常都不得导致巡检报告缺失 |
| 5 | **模型不得修改 findings** | 补丁只能"修复"风险，不能"删除"风险记录。修复前后两条记录都要保留，用于回归比对 |

---

## 11. 对 `architecture.md`（V4.0）的修改清单

合并时按以下清单逐节修改，产出 V5.0 单一自包含文档。

| # | 原位置 | 修改内容 |
|---|---|---|
| 1 | §2 P2 | 「删掉 agent 层后，输出从『可执行报告』退化为『风险清单』」→ 改为「**删掉 agent 层后，系统无法生成补丁草案**，输出只剩风险清单与文字建议」。这是明确的能力丧失 |
| 2 | §1.2 一句话定位 | 保持「离线网络配置合规巡检工具」不变；在副标题补一句「支持补丁草案生成与机械验证」 |
| 3 | §4.2 `Finding` | 新增字段 `patchable: bool` |
| 4 | §5.1 `@rule` | 新增字段 `patchable: bool = False` |
| 5 | §6.2 工具清单 | 10 → 12，新增 `propose_patch`、`verify_patch`（定义见本文档 §5） |
| 6 | §7.5 | 新增 **M6：补丁生成与闭环验证**，说明它如何使 P2 成立（引用本文档 §3） |
| 7 | §7.6 终止判定 | 增加「补丁预算耗尽 / 补丁连续失败」两行 |
| 8 | §8.2 报告结构 | 第 4 区块增加子项「**修复补丁（diff）**」，仅在 `verified=True` 时显示；第 6 区块局限声明中增加「补丁仅验证文本层有效」 |
| 9 | §9.1 指标表 | 新增三行：补丁有效率、回归率、补丁覆盖率 |
| 10 | §12.3 `Patch` / `Operation` | 用本文档 §4 的定义替换（V4.0 的版本缺 `attempt` / `verified` / `verify_result`） |
| 11 | §12.6 不做闭环的理由 | 「工作量翻倍所以全都不做」→ 改为「**生成做、应用不做**」：Phase 1 实现补丁生成与机械验证，应用与回滚留给 Phase 2/3 |
| 12 | §10.1 排期 | 在 W10 与 W11 之间插入两到三周；或压缩演示材料准备。总计 12 周 → 14—15 周 |
| 13 | 新增章节 | 建议放在 §12 之前，编号 §12，原 §12 顺延为 §13。内容即本文档 §3—§10 |

---

## 12. 禁止事项（不要"顺手优化"）

以下各项是设计边界，修改时不得移除或弱化：

1. ✗ **不得让 agent 修改 findings 本身**——补丁只能修复风险，不能消除记录
2. ✗ **不得跳过"跑全部 12 条规则"这一步**——只跑目标规则会漏掉 regressed
3. ✗ **不得用正序应用 operations**——必须倒序，否则行号漂移
4. ✗ **不得把未验证通过的 patch 放进报告**
5. ✗ **不得声称"补丁在设备上验证通过"**——只承诺文本层
6. ✗ **不得为了提升补丁有效率而缩小 patchable 范围**——覆盖率必须同时报
7. ✗ **不得在 Phase 1 实现补丁的自动应用**——那是 Phase 2
8. ✗ **不得把补丁生成设为巡检的必需步骤**——它必须是可失败的增强项

---

## 13. 验收标准

合并后的 V5.0 必须能回答以下问题，缺一不可：

1. P2 是否给出了明确的能力丧失？（答：删掉 agent 无法生成补丁）
2. 补丁的有效性由谁判定？（答：规则引擎重新跑一遍，不是模型）
3. 如何检测"修复引入新问题"？（答：regressed 集合）
4. 补丁失败时系统会怎样？（答：降级为文字建议，报告正常产出）
5. 为什么只做两条规则？（答：证明机制成立即可，范围守死）
6. 补丁会不会被自动应用到设备？（答：永不，只出 diff）
7. 补丁有效率能否被"挑软柿子"刷高？（答：不能，必须同时报覆盖率）

---

## 附录 A　面试口径

被问「你的 AI 是不是可有可无」时：

> 判定那一层不需要 AI，我从来没这么说过——我专门做了个不装模型的命令行版本，就是为了证明判定零依赖模型。
>
> 但修复方案需要。规则能告诉你「ACL 第 5 条被第 2 条覆盖」，没法告诉你「该把哪条挪到第几条、改完会不会影响另外两个接口」。这是组合问题，写不成算法。
>
> 所以我的设计是：模型生成补丁草案，然后由规则引擎把补丁应用回配置文本、重新跑一遍全部规则，看目标风险有没有真的消失、有没有引入新风险。通过才输出，不通过就让模型重来。
>
> 判定权在规则，生成权在模型。

## 附录 B　写在最后

这个机制的价值不在"agent 能改配置"，而在于：**它把「agent 有没有用」从主观判断变成了可计算的数字。** 补丁有效率和回归率，是机器算出来的，不是模型自述的。

*文档结束。*