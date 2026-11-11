# NetGuard 架构设计说明书 V3.0

> 本版是 V2.0 的修订版，**不重写全文**。V2.0 未在本版提及的章节，原文有效。
> 日期：2026-10-28　修订轮次：第 2 轮（第 1 轮有误，已更正，见 0.1）

---

## 0. 修订说明

### 0.1 先更正第 1 轮修订版的三个错误

第 1 轮修订版在只读了 V2.0 前 2KB 的情况下动笔，误砍了原文档的核心设计。现更正：

| 错误 | 第 1 轮写法 | 事实 | 处理 |
|---|---|---|---|
| 误砍多轮 | 「v1 移除 `--chat`，只做单轮」 | V2.0 第 6.1 节明确是「默认单轮 + `--chat` 多轮」，5.6 节 `MAX_TURNS=6` 已写进循环 | **撤销**，恢复 B+C 组合 |
| 误砍工具 | 「11 个 → 8 个」，删掉 `describe_rule` / `list_interfaces` | 这两个工具分别支撑 M2（线索追踪）与 P3（返回结论不返原材料），删掉即削弱承重机制 | **撤销**，只删 `check_connectivity` |
| 误判规则数 | 「14 → 12」，未说明与原意的关系 | V2.0 原文即「交付目标 12 条」，只是表格列了 14 条 | **保留修订**，但改为「执行原文 P7 的意图」 |

同时确认：`submit_findings` 命名、`list_rules` 必供、画像预过滤候选集，**V2.0 原文已全部具备**，本版不改。

### 0.2 本版最终修订清单

| # | 修订项 | 性质 |
|---|---|---|
| 1 | 排期 8 周 → 12 周，分保底/加分两段 | 新增 |
| 2 | 工具 11 → 10（仅删 `check_connectivity`） | 微调 |
| 3 | `verify_claims` 补结构化协议 | **补漏洞** |
| 4 | 无依据表述率目标 0 → ≤5%，分母改精确 | 修正 |
| 5 | **loop 结构修正：`submit_findings` 结束本轮，不结束程序** | **补 bug** |
| 6 | 明确交付哪 12 条规则 | 消歧 |
| 7 | 新增指标确定性分级 | 新增 |
| 8 | 新增 MVP 交付线（W4 达成） | 新增 |

---

## 1. 保留项：V2.0 原样执行

以下内容本版**不改动**，直接执行 V2.0 原文：

- 第 2 节七条设计原则（P1—P7）——裁决依据
- 第 3.2 节四个结构洞、第 3.3 节禁止回退清单
- 第 4.1 节依赖方向、4.2 节目录结构、4.3 节分层职责
- 第 5.1—5.4 节数据模型、`RunContext`、规则契约、工具契约
- 第 6.1 节运行形态（默认单轮 + `--chat` 多轮）
- 第 6.2 节动作空间设计（画像预过滤 + 候选内决策）
- 第 6.3 节 M1—M5 五个承重机制
- 第 6.6 节反模式清单
- 第 7.2 节 `needs` 分层、7.3 节 `known_fp`、7.4 节规则扩展契约
- 第 8.2 节语料分层、8.4 节 Agent 层指标定义
- 第 9.1 节必备配套文件、9.3 节 README 八部分
- 第 10 节风险与表述纪律

---

## 2. 修订一：排期 8 周 → 12 周

### 2.1 为什么 8 周不可能

V2.0 第 9.2 节 W1 要求：`models` + `parser` + `netutil` + 5 条规则 + `core.cli` + 首次 push。

华为 VRP 的块结构、缩进层级、`undo` 语义、`vlan batch ... to ...` 展开、ACL 规则字段抽取——单是 parser 就要 2—3 天。再叠 5 条规则（每条要正反样例），W1 一周做不完。

W2 要求 12 条规则 + 正反样例 + expected schema + pytest。12 条 × 4 件套 = 48 个交付点，一周不可能。

真实约束：单人、Python 子集水平、**同时在实习**、每周 15—20 小时。

### 2.2 修订后的 12 周排期

**第一段：保底版（W1—W4）—— 不含一行模型代码**

| 周 | 交付物 | 验收 |
|---|---|---|
| W1 | `pyproject.toml`、`core/models.py`、`core/netutil.py`、`tests/test_netutil.py` | pytest 全绿；反掩码/掩码转换全分支覆盖；**周末必须有一次 git push** |
| W2 | `core/parser.py`、`core/severity.py`、`core/rules/base.py`（`@rule`）、`core/rules/registry.py`（自动发现） | `corpus/huawei/` 全部样例解析成功；解析失败给出行号与原因 |
| W3 | 6 条规则（OSPF-004、ACL-001、ACL-004、IF-001、SEC-001、OSPF-001）+ 各带正反样例 | 6 条规则测试通过 |
| W4 | 规则补至 12 条、`core/cli.py`、`corpus/expected/` | **`python -m netguard.core.cli x.cfg` 出不装 Ollama 的完整风险列表** |

> **W4 结束 = MVP 达成 = 可写进简历开始投递。**

**第二段：加分版（W5—W12）**

| 周 | 交付物 | 验收 |
|---|---|---|
| W5 | `state.py`（`RunContext`）、`core/profile.py`（设备画像） | 同配置只解析一次；画像能区分 core/agg/access |
| W6 | `tools/registry.py`（`@tool` + pydantic + `export_schema()`）、`tools/schema.json` | schema 快照测试通过；工具可被脚本直接调用 |
| W7 | 10 个工具实现（`submit_findings` 最后） | 单工具返回 ≤ 4KB；参数错误返回结构化 error 不抛异常 |
| W8 | `agent/llm.py`（`/api/chat` + `supports_tools()` 自检 + `FakeClient`） | `FakeClient` 回放能跑通，不依赖网络 |
| W9 | `agent/loop.py`（两层循环，见修订五）、`agent/trace.py`、降级矩阵 | 单轮跑通完整轨迹；`--chat` 能接一轮追问 |
| W10 | `tools/verify.py`、`report/markdown.py` | 报告含「Agent 决策轨迹摘要」与「局限声明」 |
| W11 | `eval/` 三个脚本、`tests/` 补齐、CI、Dockerfile | CI 绿；三个指标能打印 |
| W12 | README、演示视频、冻结功能 | 只允许 bugfix |

### 2.3 超时兜底

若 12 周仍紧：砍 W11—W12 的 Docker 与演示视频，保留 **MVP + tools + 单轮 agent + 规则层指标**。这一档仍满足「Agent 承重」论证（M1/M2/M3/M5 全在单轮内）。

---

## 3. 修订二：工具 11 → 10（仅删 `check_connectivity`）

### 3.1 撤销第 1 轮的 8 工具方案

第 1 轮以「7B 模型工具选择准确率下降」为由砍掉 `describe_rule` 与 `list_interfaces`。该理由未经验证，且忽略了这两个工具的机制职责：

| 工具 | 职责 | 删掉的后果 |
|---|---|---|
| `describe_rule` | M2 线索追踪时回答「这条规则为什么这么判」 | Agent 无法确认线索含义，M2 退化为盲追 |
| `list_interfaces` | P3「定向检索，避免拉全量」 | 只能拉全量接口，违反 P3 |

### 3.2 只删一个：`check_connectivity`

理由：
1. 无真实设备，只能回放模拟数据，面试被问「你连的真机吗」时是负资产
2. V2.0 自己标注「可选；默认关闭」——**默认关闭的工具不该占 schema 位置**
3. 删掉后 M2 仍可运作（线索追踪靠 `get_interface` + `describe_rule`）

### 3.3 最终 10 个工具

| # | 工具 | 变化 |
|---|---|---|
| 1 | `get_device_profile` | 不变 |
| 2 | `list_rules` | 不变（**必须保留**：模型不知道有哪些规则就无法选择） |
| 3 | `describe_rule` | 不变 |
| 4 | `list_interfaces` | 不变 |
| 5 | `get_interface` | 不变 |
| 6 | `get_config_section` | 不变 |
| 7 | `run_rule` | 不变 |
| 8 | `get_findings` | 不变 |
| 9 | `verify_claims` | 入参协议见修订三 |
| 10 | `submit_findings` | 语义见修订五 |

**仍禁止**：`run_all_rules`、`get_logs`、`write_report`、`run_shell`（沿用 5.5 节）。

### 3.4 关于「20 条里选」的澄清

候选规则集**不是**全部规则。V2.0 第 6.2 节的画像预过滤把动作空间从 20+ 收敛到 **5—9 条**：

```
全部规则 12 条
   ↓ core/profile.py 按设备角色 + 运行能力集过滤
候选规则 5—9 条（list_rules 只返回这些）
   ↓ agent 在候选内决定执行哪些、顺序、是否追线索
```

所以 agent 面对的选择空间是 9 选 N，不是 20 选 N。这一点必须写进 README，否则「规则选择召回率」这个指标会被误读。

---

## 4. 修订三：`verify_claims` 补结构化协议（V2.0 最大漏洞）

### 4.1 问题

V2.0 第 6.3 节 M5 的例子：

```python
verify_claims(device_id, claims=[
  "GE0/0/1 的 IP 未在 OSPF 中宣告",
  "ACL 3000 的第 2 条 deny 覆盖了第 5 条 permit",
])
# → {"supported": [0], "unsupported": [1]}
```

**纯自然语言断言无法机械比对。** 要判断「这句话是否被 findings 支撑」，仍需模型理解语义——那就不是机械校验，只是多一次模型调用。而 8.3 节又要求 `report_faithfulness.py`「用规则模板 + 关键词抽取，不依赖模型」来抽断言，两处对不上。

照原文实现，W5 必然卡住。

### 4.2 修订：断言 = 自然语言正文 + 结构化定位字段

`claims[]` 的每一项改为对象，**三个字段缺一不可**：

```python
claims = [
  {
    "text":     "GE0/0/1 配置了 IP，但未被任何 OSPF network 宣告",
    "rule_id":  "OSPF-004",
    "location": "interface GigabitEthernet0/0/1",
  },
  {
    "text":     "ACL 3000 中第 5 条 permit 被第 2 条 deny 完全覆盖",
    "rule_id":  "ACL-001",
    "location": "acl 3000 rule 5",
  },
]
```

校验是纯查表，零模型参与：

```python
key = f"{c['rule_id']}@{c['location']}"
hit = key in ctx.findings
supported = bool(hit)
```

**规则**：

1. `rule_id` 必须是当前候选集内的合法 ID，否则 `unsupported` 并给 hint
2. `location` 必须与 `Finding.location` 字符串完全一致（`core` 生成，格式统一）
3. `text` 可为任意自然语言，**但只有 rule_id + location 命中时才被采信**
4. 缺任一字段 → `unsupported`，`detail` 写明缺哪个

### 4.3 报告正文怎么来

`groups[].title / reason / suggestion` 仍由模型写，但**每段必须挂 `supported_by` 索引到 claims**：

```python
groups = [
  {"title": "OSPF 区域宣告遗漏导致邻居无法建立",
   "reason": "接口 GE0/0/1 配置了 IP，但未纳入任何 OSPF network 宣告",
   "suggestion": "在 ospf 1 的 area 0 下补充 network 192.168.10.0 0.0.0.255",
   "supported_by": [0]},
]
```

**硬约束**：`supported_by` 为空或索引越界的 group，由代码直接丢弃，不进报告。

### 4.4 这样改的收益

1. `verify_claims` 变成确定性函数，可单测、可回放
2. 「无依据表述率」有了精确分母（见修订四）
3. 保留了自然语言的可读性（`text` 字段），不牺牲 M5 的展示价值
4. **反幻觉从提示词祈祷变成流程约束**——V2.0 想要的效果反而真正达成

---

## 5. 修订四：无依据表述率的目标与分母

### 5.1 V2.0 的问题

第 8.3 节：`无依据表述率 = unsupported 断言数 / 报告中的全部断言数`，目标 = 0。

- 分母靠「规则模板 + 关键词抽取」从报告正文里抽句子，**抽取本身有误差**，分母不确定
- 目标 0 是过度承诺，一处抽取误判即破

### 5.2 修订后的定义

```
无依据表述率 = unsupported 断言数 / verify_claims 提交的断言总数
```

- 分母改为「agent 实际提交的结构化断言数」，**精确可数**
- 目标 **≤ 5%**，且必须同时报样本量（如「3/68 = 4.4%」）
- 单次运行断言数 < 20 时只报绝对数，不报比率

### 5.3 另设一个更硬的指标

```
报告覆盖率 = 报告中出现的 rule_id 数 / ctx.findings 中的 rule_id 数
```

纯机械可算，分母确定，目标 = 100%。它检验「发现的都写进去了」，比无依据表述率更难糊弄。

---

## 6. 修订五：loop 结构修正（`submit_findings` 结束本轮）

### 6.1 原文的 bug

V2.0 第 5.6 节：

```python
def run(ctx, user_msg):
    for turn in range(MAX_TURNS):          # ← 多轮循环
        ...
        if call.name == "submit_findings":
            return finish(ctx, result)      # ← 直接 return，外层循环作废
```

`MAX_TURNS=6` 写在循环里，但 `submit_findings` 第一轮就 `return` 出函数——**第二轮永远不会执行**。第 6.1 节承诺的 `--chat` 多轮，在这份 loop 里跑不起来。

### 6.2 修订：拆成两层循环

```python
def run_session(ctx, llm, user_msg, chat_mode: bool):
    """外层：会话循环。单轮模式下只跑一次。"""
    reports = []
    while True:
        report = run_turn(ctx, llm, user_msg)     # 内层：单轮自主巡检
        reports.append(report)
        if not chat_mode:
            return reports
        user_msg = ui.ask_followup(report)        # 交互式追问
        if user_msg is None:                      # 用户退出
            return reports
        ctx.new_turn(user_msg)                    # 复用 RunContext，不重新解析


def run_turn(ctx, llm, user_msg):
    """内层：单轮内 agent 自主决策。submit_findings 结束本轮，不结束程序。"""
    empty_streak = 0
    for step in range(MAX_STEPS_PER_TURN):
        resp = llm.chat(ctx.prompt(), ctx.history, tools=registry.schemas())

        if not resp.tool_calls:
            if empty_streak == 0:
                ctx.history.append(NUDGE_MUST_CALL_TOOL)
                empty_streak += 1
                continue
            return degrade_turn(ctx, reason="model_idle")

        progressed = False
        for call in resp.tool_calls:
            result = registry.invoke(call.name, ctx, **call.args)
            ctx.trace.record(ctx.turn_index, step, call, result)
            if call.name == "submit_findings":
                return finish_turn(ctx, result)    # ← 结束本轮
            progressed |= result.added_count > 0

        empty_streak = 0 if progressed else empty_streak + 1
        if empty_streak >= MAX_EMPTY_STEPS:
            return degrade_turn(ctx, reason="no_new_info")

    return degrade_turn(ctx, reason="step_budget")
```

### 6.3 `submit_findings` 的语义

| 模式 | 语义 |
|---|---|
| 单轮（默认） | 提交本轮发现 → 结束本轮 → 程序结束 |
| `--chat` | 提交本轮发现 → 结束本轮 → 回到会话循环等待追问 |

**这不是文字游戏**：`submit_findings` 提交的是「本轮的结构化发现」，不是「程序结论」。名字本身就约束了它只能收结构化数据，不能收自由文本结论——这正是 V2.0 想要的语义约束。

### 6.4 多轮的关键约束（P4 验收点）

- 第 2 轮**不得重新解析配置**：`ctx.configs` 已缓存
- 第 2 轮**不得重复执行已跑过的规则**：`run_rule` 命中 `ctx.rules_run` 时直接返回缓存结果并附 `{"notice": "already_run", "result": ...}`
- 第 2 轮可直接引用第 1 轮 Finding，无需重新取证

这三条是 M4 的验收标准，也是「多轮不是重新跑一遍」的证据。

### 6.5 多轮的评测成本

M4 需要 10 个固定追问 + 人工判定，成本高于其余四个机制。因此：

- **多轮指标不计入 v1 DoD**，作为「附加展示项」写进 README
- 但 `--chat` 功能本身必须在 v1 可用（面试现场演示价值最高）

---

## 7. 修订六：明确交付哪 12 条规则

V2.0 第 7.1 节表格列 14 条，标题说「交付目标 12 条」，内部不一致。本版按 P7「范围守死」执行 12 条。

### 7.1 交付的 12 条

| ID | 规则 | 严重度 |
|---|---|---|
| OSPF-001 | 同一接口 IP 被多个 Area 的 network 宣告 | HIGH |
| OSPF-002 | network 宣告的网段内无任何本机接口 | MEDIUM |
| OSPF-003 | 进程缺失 / router-id 未配或非法 | MEDIUM |
| OSPF-004 | 接口参与 OSPF 但未被任何 network 覆盖 | HIGH |
| ACL-001 | 前置 deny 覆盖后置 permit | HIGH |
| ACL-002 | 反掩码非法 / 非连续通配符 | HIGH |
| ACL-003 | ACL 已定义但未被引用 | LOW |
| ACL-004 | ACL 为空或仅含 `deny any` 却被引用 | BLOCKER |
| IF-001 | 同设备内接口 IP 冲突或网段重叠 | HIGH |
| IF-002 | 三层接口未配 IP 或掩码非法 | MEDIUM |
| RT-001 | 静态路由下一跳不在任何直连网段 | LOW |
| SEC-001 | 开启 Telnet 且未限制源地址 | HIGH |

### 7.2 未纳入的两条

| ID | 规则 | 理由 |
|---|---|---|
| OSPF-005 | 同进程内 network 条目重复或冗余 | LOW 且判定逻辑与 OSPF-001 重叠，合并会污染两条规则的独立性 |
| RT-002 | 默认路由与明细路由冲突 / 重复 | 需路由表选路语义，单设备配置判不准，是误报源 |

两条均写入 `core/rules/ROADMAP.md`，README 的「不做什么」一节列出。

---

## 8. 修订七：指标确定性分级

V2.0 第 8.1 节给了三层指标，但未区分确定性等级。这是对外报数的口径问题。

| 层 | 指标 | 确定性 | 报数方式 |
|---|---|---|---|
| 规则层 | Precision / Recall / F1 | **完全确定** | 精确值：`P=0.91, R=0.88` |
| 报告层 | 报告覆盖率 | **完全确定**（纯查表） | 精确值 |
| 报告层 | 无依据表述率 | 半确定（分母确定，分子依赖 agent 提交集） | 绝对值 + 比率 + 样本量 |
| Agent 层 | 规则选择召回率、无效调用率、平均步数 | **不确定** | 重复 N 次，报均值与范围 |

### 8.1 Agent 层报数纪律

```
✗ 错误：「Agent 规则选择召回率 87%」
✓ 正确：「10 个样本 × 5 次重复，规则选择召回率 0.86—0.90，均值 0.88」
```

原因：`temperature=0` 不等于 100% 确定。三个不可控来源——GPU 并行累加的浮点差异、模型版本更新、上下文长度变化导致的截断位置差异。

### 8.2 不确定性影响边界（写进 README）

| 环节 | 确定性 | 影响指标 |
|---|---|---|
| 配置解析 | 确定 | — |
| 规则判定 | 确定 | 误报率、精确率 |
| Agent 选规则 | 不确定 | 规则选择召回率（覆盖率） |
| Agent 步数 | 不确定 | 平均步数、耗时 |

**结论：Agent 走错路，结果不会错，只会漏。** 误报率不受 Agent 影响——规则没命中就不会报；只有覆盖率受影响。

---

## 9. 修订八：新增 MVP 交付线

V2.0 的 DoD 是 7 条全满才算完成，意味着 W6 前没有任何可写进简历的产物。

### 9.1 MVP 线（3 条，W4 达成）

1. `python -m netguard.core.cli corpus/huawei/core_sw_01.cfg` 在**不安装 Ollama**的情况下输出 12 条规则的完整风险列表
2. `pytest` 全绿
3. `eval/rule_eval.py` 在 `corpus/external/` 上产出 P/R/F1 并打印

> 此时项目不含任何模型代码，但已是完整、可量化的网络巡检工具。**这是保底。**

### 9.2 完整 DoD（7 条，W12 达成）

沿用 V2.0 第 11 节，仅补充第 8 条：

1. `netguard.core.cli x.cfg` 不装 Ollama 也能出风险列表（验证 P4）
2. `netguard scan x.cfg` 产出 Markdown 报告，trace 中可见 ≥ 4 次工具调用（验证 P2）
3. `netguard scan --chat x.cfg` 能接一轮追问，且第 2 轮不重新解析配置（验证 P4 + M4）
4. `pytest` 全绿；`rule_eval.py` 在 `external/` 上产出 P/R/F1；`report_faithfulness.py` 输出无依据表述率与报告覆盖率
5. CI 在 push 后自动跑通上述 4 项
6. 故意传入空文件 / 乱码 / 无 OSPF 配置，程序降级但仍产出报告，不崩溃
7. **删除 `agent/` 后，系统只能做全候选规则平铺输出，无法做规则选择、线索追踪、归因合并、报告自校验**（证明 P2）
8. `--chat` 第 2 轮 `run_rule` 对已跑规则返回 `already_run` 而非重跑（证明状态复用）

---

## 10. 与 V2.0 的差异汇总

| 章节 | V2.0 | V3.0 |
|---|---|---|
| 5.5 工具清单 | 11 个 | 10 个（删 `check_connectivity`） |
| 5.6 Agent 循环 | `submit_findings` 直接 return，多轮不可用 | 拆两层循环，`submit_findings` 结束本轮 |
| 6.3 M5 | 自然语言断言 | 自然语言 + `rule_id` + `location` 三字段 |
| 7.1 规则 | 列 14 说 12 | 明确 12 条 |
| 8.1 指标 | 三层 | 三层 + 确定性分级 |
| 8.3 无依据表述率 | 目标 0，分母为报告全部断言 | 目标 ≤5%，分母为提交断言数；另设报告覆盖率 |
| 9.2 排期 | 8 周 | 12 周，W4 达成 MVP |
| 11 DoD | 7 条 | 7 条 + 第 8 条（多轮状态复用） |

其余章节全部沿用 V2.0 原文。

---

## 11. 仍需作者确认的两件事

| 事项 | 为什么只能你做 |
|---|---|
| 模型选型 | `ollama show <model>` 看 template 是否含 tools。首选 qwen2.5:7b，备选 qwen3:8b。不支持 tools 则整个 agent 层失效 |
| 外部语料 | ≥5 份非自造配置。这是 README 指标唯一合法的数据来源 |

---

*与 V2.0 冲突时以本版为准；本版未涉及处以 V2.0 为准；两者均与 V2.0 第 2 节七条原则冲突时，以原则为准。*
