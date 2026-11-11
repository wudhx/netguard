# NetGuard 架构设计说明书 V4.0

> **本版为单一自包含全文。V2.0 与 V3.0 作废，不再需要合并阅读。**
> 日期：2026-10-29
> 变更来源：`architecture-v3-issues.md` 七项问题

---

## 0. 本版变更

### 0.1 七项问题处理

| 来源 | 问题 | 处理 |
|---|---|---|
| 问题 1 | `empty_streak` 按「新增 finding」判定，健康配置会误降级 | 改为按「重复调用」判定（§7.4） |
| 问题 2 | `findings` 以 `rule_id@location` 为键会覆盖丢失 | value 改为 `list[Finding]`（§4.3） |
| 问题 3 | 「无依据表述率」名实不符 | 拆分事实层/归因层，指标改名（§8） |
| 问题 4 | 规则总数口径三处矛盾 | 明确「清单 18 / 实现 12 / 候选 5—9」（§5.2、§7.2） |
| 问题 5 | 缺「确定性缺陷 vs 规范建议」维度 | 新增 `Nature` 枚举（§4.1、§5.3） |
| 问题 6 | `Role` 枚举未定义 | 定义取值、判定条件、兜底（§4.1、§7.3） |
| 问题 7 | 交付物为增量补丁 | 合并为本文档 |

### 0.2 术语约定：两套编号不要混

本文档有两套独立编号，写作与讨论时严格区分：

| 编号 | 含义 | 示例 |
|---|---|---|
| **V4.0 / V3.0 / V2.0** | **文档**版本，指架构说明书本身的修订轮次 | 「V3.0 第 6.1 节」= 上一版文档的某一节 |
| **Phase 1 / 2 / 3** | **产品**阶段，指工具能力的演进 | 「Phase 1 只做只读巡检」= 当前交付范围 |

三条硬规则：

1. 文档版本一律大写 `V`，产品阶段一律写 `Phase`，**不使用 v1/v2/v3**（与文档版本撞形，是上一版被追问的原因）
2. 提到「当前交付范围」时只写 `Phase 1`
3. 引用历史文档时才写 `V2.0` / `V3.0`，且视为已作废

---

## 1. 项目定位与约束

### 1.1 现实约束

| 约束 | 内容 |
|---|---|
| 作者 | 单人，Python 子集水平，无企业级项目经验 |
| 时间 | 12 周，每周 15—20 小时，与实习并行 |
| 环境 | 无真实网络设备，仅离线配置文件 |
| 目标 | 2027 年春招，同时面向「网络/运维」与「Agent/AI 应用」两类岗位 |

### 1.2 一句话定位

**面向政企内网的离线网络配置合规巡检工具**，Agent 作为实现特性而非卖点。

### 1.3 双目标张力

同一项目要同时回答两个问题：

- 网络岗问：**你懂不懂 OSPF/ACL/路由？** → 由规则库与 `basis` 回答
- Agent 岗问：**你会不会把 LLM 接进系统并让它可靠？** → 由工具设计、两层循环、降级矩阵、评测回答

两者不冲突，因为它们是同一系统的上下两层。

### 1.4 非目标与理由

每条非目标都必须能回答「为什么不做」，否则面试被问到时就是短板。

| 非目标 | 理由 |
|---|---|
| **模型训练与微调** | 见 §1.5，单列 |
| **拓扑级规则** | 见 §1.6，单列 |
| 多厂商完整适配 | 仅华为 VRP；H3C 留 2 份配置验证 parser 可扩展。多厂商是纯工时问题，不增加任何技术深度，且会稀释「华为配置专家」这个定位 |
| 配置下发 / 设备连接 / 真实 ping | 需要真机与凭据，学生环境不具备；且下发涉及变更风险，Phase 1 只做只读巡检（闭环方案见 §12） |
| PDF 导出 | 排版是纯工程活，Markdown 已足够演示；时间应投在评测上 |
| Web UI | 同上。CLI + Markdown 报告足以展示能力，UI 只增加演示观感，不增加任何可评测的深度 |
| 通用多设备批量 | 一次一份配置。批量是循环调用，不是新能力 |

### 1.5 为什么不做模型训练与微调

**结论：能做，但不该做。** 这个区分很重要——「不会」和「评估后不做」在面试里是两回事。

| 理由 | 说明 |
|---|---|
| **数据量不够** | 微调需要数千条高质量样本。本项目语料是 12—15 份配置，差两个数量级。合成数据可以凑量，但合成数据学到的就是自己写的规则，没有增量信息 |
| **收益接近于零** | 本项目中模型的职责只有两件：选工具、写归因。7B 通用模型已能胜任。微调能提升的是「JSON 格式遵循率」与「领域词汇准确度」——前者靠 pydantic 校验 + 重试解决，后者靠 prompt 里注入 `basis` 解决。已有更便宜的解法 |
| **与差异化无关** | 本项目的稀缺性是「懂网络的 agent 工程师」，不是「会炼丹的人」。微调是算法岗的核心能力，而作者明确不投算法岗（投入产出比低） |
| **踩在短板上** | 微调涉及数据配比、loss 曲线、过拟合判断、评估集设计。这些讲不清就是负资产——面试官问「你的验证集怎么划的」答不上来，比「我没微调」难看得多 |
| **违反 P7** | 至少吃掉 2—3 周，且这 2—3 周无法产出任何可演示的东西 |

**面试标准答法**：

> 没有微调。这个项目里模型只做两件事——选工具和写归因，7B 通用模型够用。格式不稳我用 pydantic 校验加重试兜住，领域词汇不准我把规则依据注入 prompt。微调要几千条样本，我只有十几份配置，合成数据学到的还是我自己写的规则。我评估过，投入产出比不划算，所以没做。

### 1.6 为什么不做拓扑级规则

**结论：不是做不了，是单设备配置这个输入根本判不准。**

| 规则 | 单设备为什么判不了 |
|---|---|
| Area 0 必须连续 | 连续性是多设备 + 链路关系属性。单设备只能看到自己有几个 Area 0 接口，看不到对端连的是谁 |
| 端到端路由可达性 | 需要完整拓扑与各跳路由表 |
| 下一跳是否真的可达 | 需迭代路由与全设备路由表，单文件只能看出「是否直连」 |
| 默认路由跨设备冗余 | 需邻居设备配置 |

**硬做会怎样**：只能退化成启发式近似。比如「有 Area 0 接口就算连续」——这是假判定，误报率会直接毁掉 Precision，而 Precision 是本项目唯一的量化卖点。

**这不是减分项，是加分项。** 能说清「我知道这条规则需要拓扑信息，所以 Phase 1 不做，硬做就是误报」，证明真的理解 OSPF 的区域模型。硬凑一条假规则才是减分。

架构上留了口子：`Needs` 枚举已定义 `MULTI_DEVICE` / `TOPOLOGY`，`core/rules/ROADMAP.md` 记录了这些规则与不做的理由。这说明是**设计有余量**，不是没想到。

---

## 2. 七条设计原则（裁决依据）

| # | 原则 | 含义 |
|---|---|---|
| P1 | **判定与表达分离** | 对错由确定性规则判定，模型只负责归因与措辞 |
| P2 | **Agent 必须承重** | 删掉 agent 层后，系统必须丧失某项能力 |
| P3 | **工具返回结论，不返回原材料** | 默认不回配置原文，只回结构化事实 |
| P4 | **状态与纯函数分离** | `core` 无状态无 IO；`RunContext` 承载全部可变状态 |
| P5 | **一切可回放** | 每次决策落 trace，可离线复现 |
| P6 | **指标先于功能** | 没有指标的机制不进 Phase 1 |
| P7 | **范围守死** | 宁可 12 条做透，不做 18 条半成品 |

任何实现与原则冲突时，以原则为准，并在提交说明中写明冲突点。

---

## 3. 分层架构

### 3.1 依赖方向（一行原则）

```
cli → agent → tools → state → core
report ← cli
```

**单向**。`core` 不知道 `tools` 存在，`tools` 不知道 `agent` 存在。
`agent` 禁止直接调用 `core`，`report` 禁止调用模型。

### 3.2 目录结构

```
NetGuard-Ollama/
├── pyproject.toml
├── netguard/
│   ├── core/                  # 零依赖确定性层
│   │   ├── models.py          # 数据模型 + 四个枚举
│   │   ├── netutil.py         # 地址/掩码/反掩码计算
│   │   ├── parser.py          # 华为 VRP 解析
│   │   ├── profile.py         # 设备画像与 Role 判定
│   │   ├── severity.py        # 严重度规则
│   │   ├── cli.py             # 无模型命令行入口
│   │   └── rules/
│   │       ├── base.py        # @rule 装饰器 + 注册表
│   │       ├── ospf.py        # OSPF-001~004
│   │       ├── acl.py         # ACL-001~004
│   │       ├── iface.py       # IF-001~002
│   │       ├── route.py       # RT-001
│   │       ├── security.py    # SEC-001
│   │       └── ROADMAP.md     # 不实现的规则与理由
│   ├── state.py               # RunContext / Budget / TraceWriter
│   ├── tools/
│   │   ├── registry.py        # @tool + pydantic + export_schema()
│   │   ├── config.py          # 配置类工具
│   │   ├── check.py           # 规则类工具
│   │   ├── verify.py          # verify_claims
│   │   └── submit.py          # submit_findings
│   ├── agent/
│   │   ├── loop.py            # 两层循环
│   │   ├── prompt.py
│   │   ├── llm.py             # OllamaClient / FakeClient
│   │   └── trace.py
│   ├── report/
│   │   └── markdown.py
│   └── cli.py                 # 装配入口
├── corpus/
│   ├── huawei/                # 自造/改编，开发调试
│   ├── h3c/                   # 2 份，验证 parser 可扩展
│   ├── external/              # 非自造，对外指标唯一来源
│   └── expected/              # *.yaml 期望结果
├── eval/
│   ├── rule_eval.py
│   ├── agent_eval.py
│   └── report_faithfulness.py
├── tests/
├── docs/
│   ├── architecture.md        # 本文档
│   └── rules.md               # 由 registry 自动生成
├── .github/workflows/ci.yml
├── Dockerfile
└── README.md
```

### 3.3 分层职责

| 层 | 职责 | 允许 | 禁止 |
|---|---|---|---|
| `core` | 解析、计算、判定、画像 | 纯函数、dataclass | IO、网络、模型、全局状态、打印 |
| `state` | 承载一次运行的全部可变状态 | 缓存、计数、历史 | 业务判定 |
| `tools` | 参数校验、调 core、裁剪输出、写 trace | pydantic 校验、缓存读写 | 业务判定、调 LLM |
| `agent` | 组织对话、选工具、终止判定、降级 | 调 tools 与 llm | 直接调 core、直接读写文件 |
| `report` | findings → Markdown | 模板、排序、分组 | 调模型、发起工具调用 |
| `cli` | 参数解析、装配、异常兜底 | 编排 | 业务逻辑 |

---

## 4. 数据模型

### 4.1 四个枚举

```python
class Severity(Enum):
    BLOCKER = 4   # 会导致业务中断
    HIGH    = 3   # 高概率故障
    MEDIUM  = 2   # 隐患
    LOW     = 1   # 规范性问题
    INFO    = 0   # 提示（含已知误报场景）

class Nature(Enum):
    """结论强度。needs 只描述输入依赖，表达不了「是否算问题」。"""
    DEFECT = "defect"                  # 确定性缺陷，计入 Precision/Recall
    RECOMMENDATION = "recommendation"  # 规范建议，单独统计，不进主指标

class Needs(Enum):
    """判定所需输入。Phase 1 只实现 SINGLE_DEVICE。"""
    SINGLE_DEVICE = "single"
    MULTI_DEVICE  = "multi"
    TOPOLOGY      = "topology"

class Role(Enum):
    """设备角色。取值与判定条件见 §7.3。"""
    CORE    = "core"
    AGG     = "agg"
    ACCESS  = "access"
    BORDER  = "border"
    UNKNOWN = "unknown"
```

### 4.2 数据结构

```python
@dataclass
class Config:
    device_id: str
    hostname: str | None
    vendor: str                        # "huawei" | "h3c"
    version: str | None
    interfaces: dict[str, Interface]
    ospf: dict[int, OspfProcess]
    acls: dict[str, Acl]
    static_routes: list[StaticRoute]
    acl_bindings: list[AclBinding]
    has_vrf: bool                      # 出现 ip vpn-instance 即 True
    raw_lines: list[str]               # 仅供取行号

@dataclass
class Interface:
    name: str
    ip: str | None
    mask: str | None
    admin_up: bool
    description: str | None
    ospf_area: int | None
    acl_in: str | None
    acl_out: str | None
    link_type: str | None              # access / trunk / hybrid
    access_vlan: int | None
    trunk_allow: list[int]

@dataclass
class Finding:
    rule_id: str                       # "ACL-001"
    severity: Severity
    nature: Nature                     # 新增
    location: str                      # "interface GigabitEthernet0/0/1"
    line_no: int | None
    message: str                       # 一句话说清问题（由规则生成，非模型）
    evidence: str                      # 命中原文片段，≤200 字
    basis: str                         # 依据引用
    hint: str | None                   # 建议的下一步检查（供 M2 追线索）
```

### 4.3 运行期状态

```python
@dataclass
class RunContext:
    configs: dict[str, Config]
    findings: dict[str, list[Finding]]     # key = f"{rule_id}@{location}"，value 为列表
    rules_run: set[str]
    call_sigs: dict[str, Any]              # 调用签名 → 结果缓存（判重复用）
    tool_calls: int
    turn_index: int
    history: list[Turn]
    trace: TraceWriter
    budget: Budget
    claim_registry: list[dict]
    skipped_rules: dict[str, str]
    degrade_reason: str | None

    def add_findings(self, fs: list[Finding]) -> int:
        """追加去重，返回新增条数。"""
        added = 0
        for f in fs:
            key = f"{f.rule_id}@{f.location}"
            bucket = self.findings.setdefault(key, [])
            if not any(b.message == f.message and b.evidence == f.evidence for b in bucket):
                bucket.append(f)
                added += 1
        return added

    def flat_findings(self) -> list[Finding]:
        return [f for bucket in self.findings.values() for f in bucket]

    def has_finding(self, rule_id: str, location: str) -> bool:
        bucket = self.findings.get(f"{rule_id}@{location}")
        return bool(bucket)

    def new_turn(self, user_msg: str) -> None: ...
    def candidate_rules(self) -> list[RuleMeta]: ...
```

**为什么 value 改为 list**：同一规则在同一位置可能产生多条不同结论（如 IF-001 在三个接口互相重叠时，`location` 可能重复而 `message` 不同）。以字符串为键、单值为字典会静默覆盖，导致报告漏项且不留痕迹。

---

## 5. 规则库

### 5.1 规则契约

```python
@rule(
    id="ACL-001",
    title="前置 deny 覆盖后置 permit",
    severity=Severity.HIGH,
    nature=Nature.DEFECT,                       # 新增
    category="acl",
    needs=Needs.SINGLE_DEVICE,
    applies_to={Role.CORE, Role.AGG, Role.BORDER, Role.ACCESS},
    doc_ref="华为 VRP ACL 匹配顺序：自上而下，首条匹配即生效",
    known_fp="多 VRF 场景下同地址段可合法共存；出现 ip vpn-instance 时本规则跳过",
    examples={"positive": "corpus/huawei/acl_order_bad.cfg",
              "negative": "corpus/huawei/acl_order_ok.cfg"},
)
def deny_shadow_permit(cfg: Config) -> list[Finding]:
    ...
```

硬约束：

- 签名固定 `(cfg: Config) -> list[Finding]`，纯函数：不读文件、不打印、不访问网络
- 同输入必得同输出
- 规则间禁止相互调用
- `known_fp` 非空时 `Severity` 最高只能给 LOW，且报告必须显示该声明

### 5.2 规则总数口径

三处矛盾源于把三个不同概念混为一谈。明确区分：

| 口径 | 数值 | 含义 |
|---|---|---|
| **规则清单总数** | 18 | 架构设计的完整规则集 = Phase 1 实现 12 条 + §5.5 规划 6 条 |
| **Phase 1 实现数** | 12 | 本次交付的 `Needs.SINGLE_DEVICE` 规则 |
| **候选集** | 5—9 | 从 12 条中按 `Role` + 运行能力过滤后的结果 |

README 与指标中一律写清是哪个口径。

### 5.3 三维正交

原设计只有一个 `needs`，实际有三个正交维度：

| 维度 | 取值 | 回答的问题 |
|---|---|---|
| `needs` | SINGLE_DEVICE / MULTI_DEVICE / TOPOLOGY | 判定需要什么输入 |
| `nature` | DEFECT / RECOMMENDATION | 结论是缺陷还是建议 |
| `applies_to` | 一组 `Role` | 对哪些设备角色相关 |

**Phase 1 的 12 条规则全部为 `Nature.DEFECT`。** `RECOMMENDATION` 为 Phase 2 扩展预留（如「物理接口缺 description」「接入侧未配 silent-interface」这类规范建议），Phase 1 不实现。

这一点必须写进 README：**不是不知道有这类规则，是有意排除在指标之外**。

### 5.4 Phase 1 实现的 12 条

| ID | 规则 | 严重度 | 依据 |
|---|---|---|---|
| OSPF-001 | 同一接口 IP 被多个 Area 的 network 宣告 | HIGH | OSPF 区域划分原则 |
| OSPF-002 | network 宣告的网段内无任何本机接口 | MEDIUM | OSPF 宣告有效性 |
| OSPF-003 | 进程缺失 / router-id 未配或非法 | MEDIUM | 华为 VRP 配置指南 |
| OSPF-004 | 接口参与 OSPF 但未被任何 network 覆盖 | HIGH | OSPF 宣告完整性 |
| ACL-001 | 前置 deny 覆盖后置 permit | HIGH | ACL 匹配顺序语义 |
| ACL-002 | 反掩码非法 / 非连续通配符 | HIGH | 华为 VRP ACL 语法 |
| ACL-003 | ACL 已定义但未被引用 | LOW | 配置有效性 |
| ACL-004 | ACL 为空或仅含 `deny any` 却被引用 | BLOCKER | 引用即全阻断 |
| IF-001 | 同设备内接口 IP 冲突或网段重叠 | HIGH | 路由表唯一性 |
| IF-002 | 三层接口未配 IP 或掩码非法 | MEDIUM | TCP/IP 规范 |
| RT-001 | 静态路由下一跳不在任何直连网段 | LOW | 路由可达性 |
| SEC-001 | 开启 Telnet 且未限制源地址 | HIGH | 等保 2.0 身份鉴别 |

### 5.5 不实现的规则（写入 `core/rules/ROADMAP.md`）

| 规则 | 不实现的理由 |
|---|---|
| Area 0 必须连续 | 连续性是多设备 + 链路关系属性，单份配置无法判定 |
| 端到端路由可达性 | 需完整拓扑与各跳路由表 |
| 下一跳是否真的可达 | 需迭代路由与全设备路由表，单文件只能看出「是否直连」 |
| 默认路由跨设备冗余 | 需邻居设备配置 |
| OSPF-005 network 条目重复 | LOW 且判定逻辑与 OSPF-001 重叠 |
| RT-002 默认路由与明细路由冲突 | 需路由表选路语义，单设备判不准，是误报源 |

> **这是加分项而非减分项**：能说清「我知道这条规则需要拓扑信息，所以 Phase 1 不做，硬做就是误报」，比硬凑一条假规则强得多。

### 5.6 误报登记（`known_fp`）

三类必须在元数据中声明，报告中原样展示：

1. **VRF 场景**：出现 `ip vpn-instance` 时，IF-001 与 ACL 类规则可能误报 → 检测到即降为 INFO 并注明
2. **ACL 隐式默认行为**：华为 ACL 未匹配时的默认动作**取决于调用模块**（`traffic-filter` 默认 deny；NAT/策略路由默认 permit）。本工具只报「显式规则间的覆盖关系」，不对隐式默认下断言
3. **递归静态路由**：RT-001 下一跳不在直连网段是合法的 → 定 LOW 并注明

### 5.7 扩展契约

新增一条规则的成本必须是：

1. 在对应类别文件写一个纯函数
2. 加 `@rule` 元数据
3. 在 `corpus/` 加正反两个样例，`expected/` 加期望结果

**除此之外不得改动任何文件**——`registry` 自动发现，`docs/rules.md` 自动生成，`eval` 自动纳入。若需改其他地方，说明扩展契约设计失败，应修契约而非改规则。

---

## 6. 工具层

### 6.1 工具契约

```python
@tool(
    name="run_rule",
    description="对指定设备的指定规则执行校验。调用前请先用 list_rules 查看可用规则。",
    params={
        "device_id": ("string", "设备标识，来自 get_device_profile"),
        "rule_id":   ("string", "规则 ID，如 OSPF-002，必须是 list_rules 返回的候选之一"),
    },
    returns="RuleResult: {rule_id, hit_count, findings[], added_count, cached}",
)
def run_rule(ctx: RunContext, device_id: str, rule_id: str) -> RuleResult:
    ...
```

硬约束：

1. **参数说明必须显式书写**，不得依赖类型注解自动推导——类型注解只能推出 `string`，推不出「这里要接口名还是规则 ID」
2. 参数用 pydantic 校验；校验失败**不抛异常给模型**，返回 `{"error": "invalid_params", "detail": ..., "hint": "..."}`
3. `registry.py` 必须能 `export_schema()` 导出 `tools/schema.json`；CI 中与仓库快照比对，不一致即失败
4. 单工具返回 ≤ 4KB，超出必须分页或摘要

### 6.2 工具清单（10 个）

| # | 工具 | 输入 | 输出（结论型） | 支撑机制 |
|---|---|---|---|---|
| 1 | `get_device_profile` | `device_id` | 主机名/厂商/接口数/三层接口数/运行协议/**Role**/候选规则 ID 列表 | M1 |
| 2 | `list_rules` | `device_id` | 候选规则 `[{id,title,severity,nature,basis}]`，已按画像预过滤 | M1 |
| 3 | `describe_rule` | `rule_id` | 判什么/依据/known_fp/正反样例片段 | M2 |
| 4 | `list_interfaces` | `device_id`, `filter?` | 接口摘要列表 | P3 |
| 5 | `get_interface` | `device_id`, `if_name` | 单接口结构化事实 | M2 |
| 6 | `get_config_section` | `device_id`, `section` | 结构化对象；`raw=True` 才回原文 | P3 |
| 7 | `run_rule` | `device_id`, `rule_id` | `{rule_id, hit_count, findings[], added_count, cached}` | 核心动作 |
| 8 | `get_findings` | `device_id`, `severity?`, `rule_id?` | 已发现集合 | M3 |
| 9 | `verify_claims` | `device_id`, `claims[]` | `{supported[], unsupported[], detail{}}` | M5 |
| 10 | `submit_findings` | `device_id`, `groups[]`, `skipped_rules`, `summary` | 提交并结束本轮 | 唯一正常终止 |

**明确禁止**：`run_all_rules`（会让 Agent 退化为两步脚本）、`get_logs`（Phase 1 无日志来源）、`check_connectivity`（无真实设备）、`write_report`（渲染必须确定性）、`run_shell`（安全边界，永久禁止）。

---

## 7. Agent 层

### 7.1 运行形态

- **默认（单轮）**：一次巡检 = 一条决策轨迹 = 一份报告。要点是「决策」而非「对话」
- **`--chat`**：报告产出后可继续追问，复用 `RunContext`

理由：单轮便于评测（一次运行一个样本），多轮便于演示（面试现场最有说服力）。二者共用同一套工具与状态。

### 7.2 动作空间：确定性预过滤 + 候选内决策

```
规则清单 18 条（设计 = 实现 12 + 规划 6）
   ↓ Phase 1 只实现 Needs.SINGLE_DEVICE 的 12 条
Phase 1 规则 12 条
   ↓ core/profile.py 按 Role + 运行能力过滤
候选集 5—9 条（list_rules 只返回这些）
   ↓ Agent 在候选内决定
① 执行哪些  ② 按什么顺序  ③ 什么时候停
```

**关于 M1 论证强度的诚实说明**：

12 条规则时，过滤幅度为 3—7 条，选择空间不宽。M1 的承重强度主要来自后两个维度——**执行顺序**与**终止判断**，而非「从大池子里筛选」。

面试被问「12 条规则能有什么选择」时的答法：

> 单看条数确实不多。但 agent 要决定的不只是选哪几条，还有按什么顺序查、查到什么程度算够。健康设备上 5 条规则全过、零发现，agent 要判断能不能收工；有问题的设备上，第一条规则命中后要不要顺着 hint 追下去，这个决策没有脚本能替。

### 7.3 Role 判定与兜底

```python
def infer_role(cfg: Config) -> Role:
    l3_count = len(cfg.l3_interfaces())
    has_ospf = bool(cfg.ospf)
    has_default_route = any(r.dest == "0.0.0.0" and r.mask == "0.0.0.0" for r in cfg.static_routes)
    has_wan_acl = any(b.interface.startswith(("GE", "XGE", "Serial")) for b in cfg.acl_bindings)

    if has_default_route and has_wan_acl:
        return Role.BORDER
    if l3_count >= 4 and has_ospf:
        return Role.CORE
    if 2 <= l3_count <= 3 and has_ospf:
        return Role.AGG
    if l3_count <= 1 or not has_ospf:
        return Role.ACCESS
    return Role.UNKNOWN
```

**兜底规则（必须实现）**：`Role.UNKNOWN` 时 `candidate_rules()` 返回**全部 12 条**，并在报告头部标注「设备角色未识别，已放宽候选集至全量」。

理由：候选集为空会让 Agent 无规则可跑，且该情形不被任何降级分支覆盖——宁可多查，不可空转。

### 7.4 两层循环

```python
MAX_STEPS_PER_TURN = 12
MAX_REPEAT_STEPS   = 3      # 连续重复调用容忍度
MAX_TURNS          = 6


def run_session(ctx, llm, user_msg, chat_mode: bool):
    """外层：会话循环。单轮模式只跑一次。"""
    reports = []
    while True:
        report = run_turn(ctx, llm, user_msg)
        reports.append(report)
        if not chat_mode:
            return reports
        user_msg = ui.ask_followup(report)
        if user_msg is None:
            return reports
        ctx.new_turn(user_msg)          # 复用 RunContext，不重新解析
        ctx.turn_index += 1


def run_turn(ctx, llm, user_msg):
    """内层：单轮自主巡检。submit_findings 结束本轮，不结束程序。"""
    repeat_streak = 0
    for step in range(MAX_STEPS_PER_TURN):
        resp = llm.chat(ctx.prompt(), ctx.history, tools=registry.schemas())

        if not resp.tool_calls:
            if repeat_streak == 0:
                ctx.history.append(NUDGE_MUST_CALL_TOOL)
                repeat_streak += 1
                continue
            return degrade_turn(ctx, reason="model_idle")

        for call in resp.tool_calls:
            if call.name == "submit_findings":
                return finish_turn(ctx, result)      # ← 结束本轮

            sig = ctx.call_signature(call)           # "run_rule:OSPF-001"
            if sig in ctx.call_sigs:
                repeat_streak += 1                   # 重复调用 = 无进展
                result = ctx.call_sigs[sig]
            else:
                result = registry.invoke(call.name, ctx, **call.args)
                ctx.call_sigs[sig] = result
                repeat_streak = 0                    # 任何新调用 = 有进展

            ctx.trace.record(ctx.turn_index, step, call, result)

        if repeat_streak >= MAX_REPEAT_STEPS:
            return degrade_turn(ctx, reason="repeated_calls")

    return degrade_turn(ctx, reason="step_budget")
```

**为什么改判定对象**（问题 1 的修法）：

原逻辑用 `added_count > 0` 判进展。但一台**配置健康**的设备上，每条规则都返回 0 条 finding——这是正常结果，不是「无新信息」。连续两条规则未命中就降级，会让报告「表面成功、实际只覆盖 2 条规则」，而且触发条件是最常见场景。

修正后：**「进展」= 发生了一次非重复调用**。`run_rule(IF-001)` 返回 0 条是有效信息（IF-001 没问题），记为进展；第二次调用 `run_rule(IF-001)` 才是无进展。

### 7.5 让 Agent 承重的五个机制

#### M1 规则选择与终止判断

**机制**：只提供 `run_rule(rule_id)`，不提供全量执行。Agent 必须先看画像与候选清单，再决定执行哪些、什么顺序、何时停止。未执行的规则与理由必须写进报告。

**为什么批处理做不到**：批处理只能全跑。全跑会产生大量与设备角色无关的告警（在接入交换机上报「未运行 OSPF」），噪声淹没真问题；且批处理没有「什么时候够了」的判断。

**可评测**：候选集内应跑规则（人工标注）vs 实际执行 → 召回率与精确率。

#### M2 线索追踪

**机制**：`Finding.hint` 携带「建议的下一步」，Agent 自主决定是否跟进。例如规则报「本接口 IP 未被任何 OSPF network 宣告」→ hint 提示「检查该接口是否应参与 OSPF」→ Agent 调 `get_interface` 与 `describe_rule` 确认，再决定是否升级严重度。

**为什么批处理做不到**：批处理在规则层就结束了，没有「顺着线索再查一层」的能力。这层追问往往是发现真因的关键（是配置漏了，还是这台设备本就不该跑 OSPF）。

**可评测**：trace 中「由 hint 触发的后续调用」比例；人工抽样判定追踪是否有效。

#### M3 归因合并

**机制**：多条 finding 可能指向同一根因。Agent 用 `get_findings` 汇总后，把平铺的 N 条归并为 M 个问题组（M < N），并为每组写归因说明。

**为什么批处理做不到**：批处理只能按规则平铺输出；归并需要语义理解。

**可评测**：问题组数 vs 人工标注根因数。

> 边界：归并是**表达层**操作，不改变任何 Finding 的判定结果——符合 P1。

#### M4 多轮追问

**机制**：`ctx.history` 承接上下文，工具选择随追问变化。追问可直接引用上一轮 Finding，不重新解析。

**为什么批处理做不到**：批处理是一次性的，无状态。

**可评测**：设计 10 个固定追问，统计「是否在 3 步内给出有 findings 支撑的答案」。**该指标不计入 Phase 1 DoD**，作为附加展示项。

#### M5 报告事实自校验

**机制**：Agent 提交前**必须**调用 `verify_claims`，把准备写进报告的每条归因交给工具做机械比对；`unsupported` 非空时必须删改，最多重试 1 次，仍不通过由代码强制删段。

**为什么这是关键**：把「反幻觉」从提示词祈祷变成**流程约束 + 可测量指标**。同时让 Agent 多了一个真实步骤：生成 → 自查 → 修正。

详见 §8.3。

### 7.6 终止判定

| 条件 | 触发 | 结果 |
|---|---|---|
| 正常终止 | 调用 `submit_findings` | 出报告，状态 `success` |
| 重复调用 | 连续 3 次同工具同参 | 出报告（部分），`degraded:repeated_calls` |
| 单轮步数耗尽 | 单轮 > 12 步 | 出报告（部分），`degraded:step_budget` |
| 轮次耗尽 | 多轮 > 6 轮 | 出报告，`degraded:turn_budget` |
| 模型空转 | 连续无 `tool_calls` 且已 nudge 一次 | 降级为全候选规则 + 模板报告，`degraded:model_idle` |

**硬要求**：任何路径都必须产出报告。禁止「程序崩溃 → 什么都没有」。

### 7.7 失败与降级矩阵

| 故障 | 检测 | 处理 |
|---|---|---|
| 模型不支持 tools | 启动自检探测 | 跑全部候选规则 → 模板报告，头部标注「降级模式」 |
| 参数校验失败 | pydantic `ValidationError` | 返回 `{error, detail, hint}`，最多重试 2 次；仍失败则跳过并记 trace |
| 重复调用 | `call_sigs` 命中 | 返回缓存结果 + `{"notice": "already_called"}` |
| 未知工具名 | registry 查不到 | 返回可用工具名清单 |
| 单工具执行异常 | try/except | 返回 `{"error": "tool_failed"}`, 不中断循环 |
| 模型超时 | llm 层 | 重试 1 次 → 降级 |
| `verify_claims` 全部 unsupported | `supported` 为空 | 丢弃所有 groups，报告退化为 findings 平铺表 + 模板归因，`degraded:no_supported_claims` |
| 报告为空 | 渲染后断言 | 兜底：直接渲染 findings 平铺表 |

### 7.8 反模式清单（出现即驳回）

1. ✗ 提供 `run_all_rules` 让模型一把梭
2. ✗ 把全部配置原文塞进 system prompt
3. ✗ 让模型直接判断「这条配置对不对」
4. ✗ 无 trace、无预算、无降级
5. ✗ 报告由模型整篇生成
6. ✗ 多轮实现为「每次重新解析 + 重新全量检查」
7. ✗ 用「新增 finding 数」判进展（健康设备会误降级）
8. ✗ findings 用单值字典存储（会静默覆盖）

---

## 8. 报告与自校验

### 8.1 事实层与归因层分离

这是本版最重要的口径修正。报告由两部分组成，来源与可信度完全不同：

| 层 | 内容 | 来源 | 确定性 |
|---|---|---|---|
| **事实层** | 严重度、位置、证据片段、依据、规则 ID | `Finding` 字段直接渲染 | **100% 确定**，模型不参与 |
| **归因层** | 问题组的标题、原因分析、整改建议 | 模型生成，必须挂 `supported_by` | 需校验 |

原指标「无依据表述率」把两层的句子混在一起测，既测不准（事实层本来就 100% 有依据），又让模型写的错误 `text` 蒙混过关。

### 8.2 报告结构（6 个区块）

1. 巡检对象（设备、配置行数、解析时间、厂商版本、**Role**）
2. 结论摘要（按严重度计数）
3. 问题分组（按根因归并）
4. 每条问题：严重度、位置、证据、依据、整改建议、**规则 ID**
5. **Agent 决策轨迹摘要**（执行了哪些规则、跳过了哪些及原因）
6. 局限声明（确定性检查、存在误报、known_fp 清单、需人工复核）

### 8.3 `verify_claims` 协议

`claims[]` 每项三个字段，缺一不可：

```python
claims = [
  {
    "text":     "GE0/0/1 配置了 IP，但未被任何 OSPF network 宣告",
    "rule_id":  "OSPF-004",
    "location": "interface GigabitEthernet0/0/1",
  },
]
```

校验为纯查表：

```python
supported = ctx.has_finding(c["rule_id"], c["location"])
```

规则：

1. `rule_id` 必须是当前候选集内合法 ID
2. `location` 必须与 `Finding.location` 完全一致
3. `text` 可为任意自然语言，**但只有前两个字段命中时才被采信**
4. 缺任一字段 → `unsupported`，`detail` 写明缺哪个

`groups[].supported_by` 必填，索引到 claims；为空或越界的 group 由代码丢弃。

### 8.4 指标定义（改名）

| 指标 | 定义 | 目标 |
|---|---|---|
| **归因引用有效率** | 有效引用的 group 数 / 提交的 group 数 | ≥ 95% |
| **报告覆盖率** | 报告中出现的 rule_id 数 / `ctx.findings` 中的 rule_id 数 | 100% |
| 事实层依据率 | 报告事实层字段全部来自 Finding | 100%（结构保证，无需测） |

**命名理由**：`verify_claims` 校验的是「这条归因是否指向一条真实发现」，不是「这句话说得对不对」。叫「归因引用有效率」才名实相符。

**必须写进 README 的说明**：

> 本工具不校验归因文字的语义正确性——那需要另一次模型判断，与「机械可验」矛盾。本工具保证的是：**每一条归因都指向一条真实存在的规则发现，且该发现的严重度、位置、证据由确定性代码渲染**。

这段话本身就是面试时的加分项：能说清指标的边界，比报一个好看的数字更可信。

---

## 9. 评测

### 9.1 三层指标 + 确定性分级

| 层 | 文件 | 指标 | 确定性 | 报数方式 |
|---|---|---|---|---|
| 规则层 | `rule_eval.py` | 逐规则 P/R/F1、误报率 | **完全确定** | 精确值 |
| 报告层 | `report_faithfulness.py` | 归因引用有效率、报告覆盖率 | 确定（纯查表） | 精确值 |
| Agent 层 | `agent_eval.py` | 规则选择召回率、无效调用率、终止正确率、平均步数 | **不确定** | 重复 N 次，报均值与范围 |

目标值：规则层 external 语料上 P ≥ 0.85、R ≥ 0.80；Agent 层选择召回 ≥ 0.85、无效调用 ≤ 10%、平均步数 ≤ 8。

### 9.2 语料分层

- `corpus/huawei/`、`corpus/h3c/`：自造或改编，开发调试用
- `corpus/external/`：**非自造**（公开样例、教材习题、eNSP 导出），每份文件头标注 `source:`
- **对外声明的指标必须基于 `external/` 计算**；自造语料上的分数只能作回归测试

`corpus/expected/*.yaml` schema：

```yaml
device_id: core_sw_01
source: "教材《路由交换技术》第 7 章习题改编"
expect:
  - rule_id: OSPF-004
    location: "interface GigabitEthernet0/0/1"
    line_no: 42
```

### 9.3 Agent 层指标定义

| 指标 | 定义 |
|---|---|
| 规则选择召回率 | 人工标注「应执行」集合 ∩ 实际执行 / 标注集合 |
| 无效调用率 | （参数错误 + 重复调用 + 零信息增益调用）/ 总调用 |
| 终止正确率 | 人工判定「本可继续发现更多问题」却提前提交的比例，取反 |
| 平均步数 | 每次巡检的工具调用次数均值 |

### 9.4 报数纪律

```
✗ 错误：「Agent 规则选择召回率 87%」
✓ 正确：「10 个样本 × 5 次重复，规则选择召回率 0.86—0.90，均值 0.88」
```

原因：`temperature=0` 不等于 100% 确定。三个不可控来源——GPU 并行累加的浮点差异、模型版本更新、上下文长度变化导致的截断位置差异。

### 9.5 不确定性影响边界（写进 README）

| 环节 | 确定性 | 影响指标 |
|---|---|---|
| 配置解析 | 确定 | — |
| 规则判定 | 确定 | 误报率、精确率 |
| Agent 选规则 | 不确定 | 规则选择召回率（覆盖率） |
| Agent 步数 | 不确定 | 平均步数、耗时 |

**结论：Agent 走错路，结果不会错，只会漏。** 误报率不受 Agent 影响——规则没命中就不会报；只有覆盖率受影响。

---

## 10. 排期与交付

### 10.1 12 周排期

**第一段：保底版（W1—W4），不含一行模型代码**

| 周 | 交付物 | 验收 |
|---|---|---|
| W1 | `pyproject.toml`、`models.py`、`netutil.py`、`tests/test_netutil.py` | pytest 全绿；**周末必须有一次 git push** |
| W2 | `parser.py`、`severity.py`、`rules/base.py`（`@rule`）、`rules/registry.py` | `corpus/huawei/` 全部样例解析成功，失败给行号与原因 |
| W3 | 6 条规则 + 正反样例 | 6 条规则测试通过 |
| W4 | 规则补至 12 条、`core/cli.py`、`corpus/expected/` | **`python -m netguard.core.cli x.cfg` 出不装 Ollama 的完整风险列表** |

**第二段：加分版（W5—W12）**

| 周 | 交付物 | 验收 |
|---|---|---|
| W5 | `state.py`、`core/profile.py`（含 Role 判定与兜底） | 同配置只解析一次；UNKNOWN 时返回全量候选 |
| W6 | `tools/registry.py`、`tools/schema.json` | schema 快照测试通过 |
| W7 | 10 个工具实现 | 单工具返回 ≤ 4KB；参数错误返回结构化 error |
| W8 | `agent/llm.py`（`/api/chat` + `supports_tools()` + `FakeClient`） | `FakeClient` 回放跑通，不依赖网络 |
| W9 | `agent/loop.py`（两层）、`trace.py`、降级矩阵 | 单轮跑通完整轨迹；`--chat` 能接一轮追问 |
| W10 | `tools/verify.py`、`report/markdown.py` | 报告含轨迹摘要与局限声明 |
| W11 | `eval/` 三个脚本、CI、Dockerfile | CI 绿；三个指标能打印 |
| W12 | README、演示视频、冻结功能 | 只允许 bugfix |

### 10.2 MVP 线（W4 达成）

1. `python -m netguard.core.cli corpus/huawei/core_sw_01.cfg` 在**不装 Ollama** 时输出 12 条规则完整风险列表
2. `pytest` 全绿
3. `eval/rule_eval.py` 在 `corpus/external/` 上产出 P/R/F1

> 此时项目不含任何模型代码，但已是完整可量化的网络巡检工具。**这是保底，W4 即可写简历投递。**

### 10.3 完整 DoD（8 条，W12 达成）

1. `netguard.core.cli x.cfg` 不装 Ollama 也能出风险列表（验证 P4）
2. `netguard scan x.cfg` 产出 Markdown 报告，trace 中可见 ≥ 4 次工具调用（验证 P2）
3. `netguard scan --chat x.cfg` 能接一轮追问，第 2 轮不重新解析配置（验证 P4 + M4）
4. `pytest` 全绿；`rule_eval.py` 在 `external/` 上产出 P/R/F1；`report_faithfulness.py` 输出归因引用有效率与报告覆盖率
5. CI 在 push 后跑通上述 4 项
6. 传入空文件 / 乱码 / 无 OSPF 配置，程序降级但仍产出报告，不崩溃
7. **删除 `agent/` 后，系统只能做全候选规则平铺输出，无法做规则选择、线索追踪、归因合并、报告自校验**（证明 P2）
8. `--chat` 第 2 轮 `run_rule` 对已跑规则返回 `already_run` 而非重跑（证明状态复用）

---

## 11. 风险与表述纪律

### 11.1 技术风险

| 风险 | 影响 | 应对 |
|---|---|---|
| 模型不支持 tools | agent 层失效 | 启动自检；不支持则降级并标注 |
| 解析器对真实格式兼容不足 | 语料跑不通 | 优先用 eNSP 导出验证；格式偏差以真实配置为准 |
| 指标不达目标 | 无法形成量化卖点 | 缩减规则范围保指标可信，而非堆规则数 |
| 时间不足 | 交付不完整 | W4 保底线，随时可停 |

### 11.2 表述纪律

1. 不说「自研大模型」，如实说明模型来自开源
2. 简历主标题写「离线网络配置合规巡检工具」，Agent 作为实现特性
3. 指标必须注明语料来源（external / 自造）与样本量
4. Agent 层指标必须报分布，不报单次数值
5. 主动声明边界：单设备视角、仅华为 VRP、规则不等同于等保测评结论

---

## 12. 演进路线：从「查」到「改」到「验」的闭环

Phase 1 只做只读巡检。但「发现问题之后呢」这个问题必须有答案——否则项目看起来是半截的。

本节定义 Phase 2 / Phase 3 的范围，**Phase 1 不实现，但架构必须留出接口**。

### 12.1 三段演进

```
Phase 1（当前）  查：配置 → 解析 → 规则 → 风险清单
                              ↓
Phase 2          改：风险 → 生成补丁（diff）→ 人工审核 → 应用
                              ↓
Phase 3          验：应用后重新解析 → 规则复验 → 确认风险消除且无新增
```

### 12.2 三条安全约束（这是整个闭环的精髓）

| # | 约束 | 理由 |
|---|---|---|
| 1 | **Agent 永不直接修改配置，只产出 diff** | 配置变更的最终决定权必须在人。工具给方案，人点确认 |
| 2 | **每次变更必须可回滚** | 应用前保存配置快照，`rollback_ref` 指向它 |
| 3 | **变更后必须复验** | 同一套 12 条规则再跑一遍，确认目标风险消失、且没有引入新风险 |

这三条不是保守，是 NetDevOps 变更管理的行业实践。能讲清这三条，比做出一个「AI 自动改配置」的 demo 可信得多。

### 12.3 Phase 2 的数据结构（预留）

```python
@dataclass
class Patch:
    device_id: str
    finding_keys: list[str]        # 本补丁修复哪些风险（rule_id@location）
    operations: list[Operation]    # 有序操作
    risk_notes: list[str]          # 副作用提示，由 agent 写
    rollback_ref: str              # 变更前快照 ID

@dataclass
class Operation:
    kind: str                      # add / modify / remove
    section: str                   # ospf / acl / interface
    target: str                    # "ospf 1 / area 0.0.0.0"
    before: str | None             # 修改前的原文（add 时为 None）
    after: str | None              # 修改后的文本（remove 时为 None）
```

### 12.4 Phase 3 的复验协议（预留）

```
apply(patch) → 生成新配置文本 → 重新 parse → 跑全部 12 条规则
    ↓
比对三个集合：
  fixed      = 原 findings 中已消失的
  remaining  = 原 findings 中仍存在的
  regressed  = 新配置中新增的（原配置没有的）
```

**`regressed` 是这套体系里最值钱的指标**——它回答「修复有没有引入新问题」。真实运维里，二次故障大多来自变更本身，不是原始故障。

### 12.5 为什么闭环里 Agent 的价值更高

Phase 1 的 agent 只决定「查什么」。Phase 2/Phase 3 的 agent 要决定：

1. **改哪几行**——同一个风险可能有多种改法（补 network 宣告 / 改接口 IP / 调整区域归属），选哪个取决于意图
2. **改成什么**——网段怎么划、ACL 规则插在第几条，需要结合上下文
3. **会不会有副作用**——改一个 OSPF network 宣告，可能影响其他区域的邻居关系

第 3 点是真正的 agent 场景：**影响分析的过程比目标难描述**。你没法预先写死「改了 A 会不会影响 B」的所有分支，只能让模型看着配置推。

这也是这个项目从「巡检工具」升级为「配置工程助手」的关键一步。

### 12.6 为什么闭环不在 Phase 1 实现

| 理由 | 说明 |
|---|---|
| 工作量 | 配置生成 + diff 引擎 + 快照回滚 + 复验比对，至少 8—10 周，超过 Phase 1 总工期 |
| 范围失控 | 会把项目从「巡检工具」变成「配置管理平台」，违反 P7 |
| 无法验证真实生效 | 没有真机，改完只能验证「文本层面正确」，无法验证「设备真的按预期转发」 |
| 会稀释核心卖点 | Phase 1 的卖点是「确定性判定 + 可量化指标」。加了修改能力，评测对象从「判定对不对」变成「改得对不对」，前者可机械验证，后者只能人工评审 |

**面试答法**：

> Phase 1 只做只读巡检，不改配置。因为改配置涉及变更风险——改错了比不改更糟。我的设计是 agent 只产出 diff，人工确认后应用，应用前存快照，应用后跑同一套规则复验，看风险有没有真的消除、有没有引入新问题。这套东西我留了接口但没做，因为工程量至少翻倍，而且没有真机验证不了实际转发效果。

这段话本身就在展示工程判断力——**知道边界在哪，比把边界推得更远更重要**。

---

## 13. 待确认（只能由作者完成）

| 事项 | 为什么只能你做 |
|---|---|
| 模型选型 | `ollama show <model>` 看 template 是否含 `tools`。首选 qwen2.5:7b，备选 qwen3:8b。不支持则 agent 层直接失效 |
| 外部语料 | ≥5 份非自造配置。这是 README 指标唯一合法来源 |

---

*本文档为单一自包含规格。与 V2.0 / V3.0 冲突时以本文档为准。*
