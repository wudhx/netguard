# NetGuard

面向政企内网的**离线网络配置合规巡检工具**。

输入华为 VRP 配置文件，输出结构化告警报告。Agent 作为实现特性而非卖点。

## 当前状态

**Phase 1 开发中。** 已完成 `core` 层的数据模型与地址计算工具。

| 模块 | 状态 |
|---|---|
| `core/models.py` | ✅ 四个枚举 + 数据模型 |
| `core/netutil.py` | ✅ 地址 / 掩码 / 反掩码计算 |
| `core/parser.py` | ⬜ 待实现 |
| `core/rules/` | ⬜ 待实现（12 条） |
| `tools/` | ⬜ 待实现（10 个工具） |
| `agent/` | ⬜ 待实现 |
| `report/` | ⬜ 待实现 |

## 设计

完整设计见 [`docs/architecture.md`](docs/architecture.md)。

依赖方向单向，禁止反向：

```
cli → agent → tools → state → core
report ← cli
```

`core` 不知道 `tools` 存在，`tools` 不知道 `agent` 存在。`agent` 禁止直接调用
`core`，`report` 禁止调用模型。

## 规则口径

三处数字含义不同，不可混用：

| 口径 | 数值 | 含义 |
|---|---|---|
| 规则清单总数 | 18 | 架构设计完整规则集 = Phase 1 实现 12 + 规划 6 |
| Phase 1 实现数 | 12 | 本次交付的 `Needs.SINGLE_DEVICE` 规则 |
| 候选集 | 5—9 | 按设备角色 + 运行能力过滤后的结果 |

**Phase 1 的 12 条规则全部为 `Nature.DEFECT`。** `RECOMMENDATION`
（如「物理接口缺 description」这类规范建议）为 Phase 2 扩展预留，
有意排除在主指标之外——不是不知道有这类规则。

## 开发

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## 非目标

以下内容**明确不做**，理由见架构文档：

- 模型训练与微调（§1.5）
- 拓扑级规则（§1.6）
- 多厂商完整适配（仅华为 VRP，H3C 留 2 份验证可扩展性）

## License

MIT
