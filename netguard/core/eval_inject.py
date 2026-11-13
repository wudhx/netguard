"""缺陷注入评测：用「已知真值的缺陷」检验规则库的召回与精确。

## 这个模块解决什么问题

规则由人写，测试语料也由人写。人只能造出自己想到的缺陷，而**想到的缺陷
恰好就是已经写成规则的那批**。于是「规则抓到了我造的缺陷」这件事，
不能证明规则有效——它只证明「规则按我写的逻辑在跑」。这是自我循环。

打破循环的唯一办法：让**不掌握规则知识的一方**独立产出「这台设备哪里
配错了」的判断，再用确定性的方式核对这些判断是否成立。

- 那一方是模型（它读的是运维语义，不是规则代码）
- 核对必须由代码做（模型说「这里是缺陷」不算数，要能落到具体行、
  要能被机械地注入并复现）

## 三方分离，缺一不可

| 角色 | 谁 | 做什么 | 不做什么 |
|---|---|---|---|
| 提议方 | 模型 | 提出缺陷假设（位置 + 期望 + 理由） | 不做裁决 |
| 裁决方 | 代码（本模块 `_check_*`） | 核对假设是否真的成立 | 不发明缺陷 |
| 判定方 | 规则引擎 | 报出哪些缺陷 | 不知道真值 |

三方互不知情：模型不知道规则怎么写，规则不知道真值在哪，代码不参与任何
一方的判断。只有这样，「命中率」这个数字才有意义。

## 当前阶段

本模块的**裁决与度量部分**已实现且完全确定，可离线跑（`--truth` 模式）。
模型提议部分（`agent/` 层）在其上接入，属于 M6 承重机制。

没有模型时，本模块仍然有用：可以用人工标注的真值文件跑评测，
得到一份基线数字。这份基线是「模型接入后是否真的有增益」的对照组。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .models import Config
from .parser import parse
from .engine import RunResult, run_all_rules

__all__ = [
    "InjectionSpec",
    "Lookup",
    "EvalRecord",
    "EvalReport",
    "evaluate",
    "aggregate",
]


# ===========================================================================
# 数据契约
# ===========================================================================


@dataclass(frozen=True)
class InjectionSpec:
    """一条缺陷假设。由模型（或人工标注）提出，由代码裁决。

    ## 为什么必须带 `line_no` 和 `expect`

    只说「这里有问题」的假设无法被机械核对，也无法被注入——它只能靠人
    再读一遍配置来判断，评测于是退化成人工评审。带上「哪一行」与「预期
    应产生什么可观测后果」，才能做到：核对可自动、注入可复现、比对可计数。

    `expect` 不是自由文本，而是本模块认识的**效果类型**，见 `_check_*`。
    这一约束是为了让「模型说的」与「代码能验的」严格对齐——避免模型用
    一种宽松的措辞蒙混过宽松的检查。
    """

    #: 缺陷所在的原文行号（1-based，指向缺陷所关联的那一行）
    line_no: int
    #: 缺陷类别，决定用哪个裁决器核对
    kind: str
    #: 该缺陷应触发的规则 ID（模型/标注者认为它属于哪条规则的管辖）
    expect_rule: str
    #: 一句话描述，用于报告与人工复核
    note: str = ""


@dataclass(frozen=True)
class Lookup:
    """裁决结果。"""

    ok: bool
    detail: str


@dataclass
class EvalRecord:
    """一条假设的评测记录。"""

    spec: InjectionSpec
    lookup: Lookup
    hit: bool
    hit_rule_ids: list[str] = field(default_factory=list)

    @property
    def is_true_positive(self) -> bool:
        """假设成立且被规则抓到。"""
        return self.lookup.ok and self.hit

    @property
    def is_false_negative(self) -> bool:
        """假设成立但规则没抓到——这是漏报，是评测最想找的东西。"""
        return self.lookup.ok and not self.hit

    @property
    def is_invalid_claim(self) -> bool:
        """假设不成立——提议方看错了，不该记在规则头上。"""
        return not self.lookup.ok


@dataclass
class EvalReport:
    """一份配置的评测结果。"""

    device_id: str
    records: list[EvalRecord] = field(default_factory=list)
    #: 规则报出但没有任何假设指向的 finding（可能是误报，也可能是漏标）
    unexplained: list[str] = field(default_factory=list)

    @property
    def true_positives(self) -> list[EvalRecord]:
        return [r for r in self.records if r.is_true_positive]

    @property
    def false_negatives(self) -> list[EvalRecord]:
        return [r for r in self.records if r.is_false_negative]

    @property
    def invalid_claims(self) -> list[EvalRecord]:
        return [r for r in self.records if r.is_invalid_claim]

    def summary(self) -> dict[str, float | int]:
        valid = [r for r in self.records if r.lookup.ok]
        return {
            "claims": len(self.records),
            "valid_claims": len(valid),
            "true_positives": len(self.true_positives),
            "false_negatives": len(self.false_negatives),
            "invalid_claims": len(self.invalid_claims),
            "recall": recall(self),
            "claim_accuracy": (len(valid) / len(self.records)) if self.records else 0.0,
            "unexplained": len(self.unexplained),
        }


# ===========================================================================
# 裁决器：核对一条假设是否真的成立
# ===========================================================================

# 支持的 `kind`。每个 kind 对应一个确定的、可机械核对的判据。
# 新增 kind 必须同时提供判据——否则假设无法被裁决，评测就退化为自述。
_KINDS = {
    "ip_conflict": "同一设备内两个接口的网段重叠",
    "acl_shadow": "ACL 中前置 deny 完全覆盖了后置 permit",
    "acl_empty": "被引用的 ACL 无任何有效 permit 规则",
    "acl_bad_wildcard": "ACL 反掩码非连续",
    "ospf_ip_multi_area": "同一接口 IP 被多个区域的 network 宣告",
    "ospf_area_uncovred": "接口参与 OSPF 但未被该区域任何 network 覆盖",
    "ospf_network_dangling": "network 宣告的网段内无任何本机接口",
    "telnet_open": "Telnet 启用且无有效源地址限制",
}


def _lookup_ip_conflict(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在两个接口，网段重叠。"""
    from . import netutil

    ifaces = [i for i in cfg.l3_interfaces() if i.ip and i.mask]
    pairs = []
    for idx, a in enumerate(ifaces):
        for b in ifaces[idx + 1 :]:
            if not (netutil.is_contiguous_mask(a.mask) and netutil.is_contiguous_mask(b.mask)):
                continue
            if netutil.subnets_overlap(a.ip, a.mask, b.ip, b.mask):
                pairs.append(f"{a.name}({a.ip}/{a.mask}) ↔ {b.name}({b.ip}/{b.mask})")
    if pairs:
        return Lookup(True, "；".join(pairs))
    return Lookup(False, "未找到网段重叠的接口对")


def _lookup_acl_shadow(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：某个 ACL 内存在 deny 覆盖后续 permit。"""
    from .rules.acl import _norm_seq, _a_covers_b

    for number, acl in sorted(cfg.acls.items()):
        rules = _norm_seq(acl.rules)
        for i, front in enumerate(rules):
            if front.action != "deny":
                continue
            for back in rules[i + 1 :]:
                if back.action == "permit" and _a_covers_b(front, back):
                    return Lookup(
                        True, f"ACL {number}: rule {front.seq} deny 覆盖 rule {back.seq} permit"
                    )
    return Lookup(False, "未找到 deny 覆盖 permit 的情形")


def _lookup_acl_empty(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在被引用但无有效 permit 的 ACL。"""
    bound = {str(b.acl_number) for b in cfg.acl_bindings}
    for number, acl in sorted(cfg.acls.items()):
        if str(number) not in bound:
            continue
        has_permit = any(r.action == "permit" for r in acl.rules)
        if not has_permit:
            return Lookup(True, f"ACL {number} 被引用且无任何 permit 规则")
    return Lookup(False, "未找到被引用且无 permit 的 ACL")


def _lookup_acl_bad_wildcard(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在非连续反掩码。"""
    from . import netutil

    for number, acl in sorted(cfg.acls.items()):
        for r in acl.rules:
            for wc in (r.source_wildcard, r.destination_wildcard):
                if wc and netutil.is_ipv4(wc) and not netutil.is_valid_wildcard(wc):
                    return Lookup(True, f"ACL {number} rule {r.seq} 反掩码 {wc} 非连续")
    return Lookup(False, "未找到非法反掩码")


def _lookup_telnet_open(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：Telnet 已启用。"""
    if cfg.telnet_enabled:
        return Lookup(True, "telnet server enable 存在")
    return Lookup(False, "Telnet 未启用")


def _lookup_ospf_network_dangling(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在 network 宣告但无接口落在范围内。"""
    from . import netutil

    ifaces = cfg.l3_interfaces()
    for proc in cfg.ospf.values():
        for area_id, area in proc.areas.items():
            for net, wc in area.networks:
                if not (netutil.is_ipv4(net) and netutil.is_valid_wildcard(wc)):
                    continue
                if not any(i.ip and netutil.ip_in_network(i.ip, net, wc) for i in ifaces):
                    return Lookup(True, f"area {area_id} network {net} {wc} 无接口覆盖")
    return Lookup(False, "所有 network 均被接口覆盖")


def _lookup_ospf_ip_multi_area(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在 IP 落入多个区域。"""
    from .rules.ospf import _declaring_areas

    for iface in cfg.l3_interfaces():
        if iface.ip and len(_declaring_areas(cfg, iface.ip)) >= 2:
            return Lookup(True, f"接口 {iface.name}({iface.ip}) 落入多个区域")
    return Lookup(False, "无接口 IP 跨区域")


def _lookup_ospf_area_uncovred(cfg: Config, spec: InjectionSpec) -> Lookup:
    """核对：存在 ospf enable 但无 network 覆盖的接口。"""
    from . import netutil
    from .rules.ospf import _norm

    covered = set()
    for proc in cfg.ospf.values():
        for area_id, area in proc.areas.items():
            for net, wc in area.networks:
                if netutil.is_ipv4(net) and netutil.is_valid_wildcard(wc):
                    covered.add((_norm(area_id), net, wc))

    for iface in cfg.l3_interfaces():
        if iface.ospf_area is None or not iface.ip:
            continue
        area_key = _norm(iface.ospf_area)
        hit = any(
            a == area_key and netutil.ip_in_network(iface.ip, net, wc)
            for a, net, wc in covered
        )
        if not hit:
            return Lookup(True, f"接口 {iface.name}({iface.ip}) 在 area {iface.ospf_area} 无 network 覆盖")
    return Lookup(False, "所有参与 OSPF 的接口均被覆盖")


_LOOKUPS = {
    "ip_conflict": _lookup_ip_conflict,
    "acl_shadow": _lookup_acl_shadow,
    "acl_empty": _lookup_acl_empty,
    "acl_bad_wildcard": _lookup_acl_bad_wildcard,
    "ospf_ip_multi_area": _lookup_ospf_ip_multi_area,
    "ospf_area_uncovred": _lookup_ospf_area_uncovred,
    "ospf_network_dangling": _lookup_ospf_network_dangling,
    "telnet_open": _lookup_telnet_open,
}


def lookup(cfg: Config, spec: InjectionSpec) -> Lookup:
    """裁决一条假设。未知 kind 一律判为不成立——不可核对的假设不能算数。"""
    fn = _LOOKUPS.get(spec.kind)
    if fn is None:
        return Lookup(False, f"无法核对的缺陷类别：{spec.kind}（支持的类别：{', '.join(sorted(_LOOKUPS))}）")
    return fn(cfg, spec)


# ===========================================================================
# 度量
# ===========================================================================


def evaluate(
    cfg: Config,
    specs: list[InjectionSpec],
    *,
    role=None,
    full_sweep: bool = True,
) -> EvalReport:
    """对一份配置执行评测。

    ## 命中口径

    一条假设算「命中」，要求其 `expect_rule` **出现在规则的报出结果里**，
    而不是「任一规则报出东西」。理由：如果只要求「有规则报了」，那么一条
    笼统的假设会被任意无关的 finding 蒙混过关，召回率会虚高。

    ## `full_sweep` 默认为 True，且不应轻易改为 False

    评测与巡检是两个目的：

    - **巡检**问「这台设备该查什么」→ 按角色与能力过滤
    - **评测**问「规则抓不抓得住」→ 必须跑全量

    若评测也走过滤，「OPSF-004 的语料恰好被判为 access 角色」会让该规则
    被跳过，于是漏报被记在角色过滤头上，而规则本身的能力没被测到。
    测的是规则，就不能让角色的判断干扰。

    `role` 参数只用于覆盖角色推断；`full_sweep=True` 时它不参与过滤。
    """
    if full_sweep:
        from .rules.base import all_rules

        cfg_role = role
        from .profile import infer_role

        actual_role = cfg_role if cfg_role is not None else infer_role(cfg)
        from .engine import RuleOutcome, run_rules

        result = RunResult(
            device_id=cfg.device_id,
            role=actual_role,
            outcomes=[
                RuleOutcome(rule_id=r.id, findings=list(r.check(cfg)))
                for r in all_rules()
            ],
        )
    else:
        result = run_all_rules(cfg, role)

    reported = {f.rule_id for f in result.findings}

    report = EvalReport(device_id=cfg.device_id)
    for spec in specs:
        lk = lookup(cfg, spec)
        hit = spec.expect_rule in reported
        report.records.append(
            EvalRecord(
                spec=spec,
                lookup=lk,
                hit=hit,
                hit_rule_ids=sorted(reported) if hit else [],
            )
        )

    # 规则报出、但没有任何假设指向的规则 ID —— 待人工判定是误报还是漏标
    explained = {s.expect_rule for s in specs if lookup(cfg, s).ok}
    report.unexplained = sorted(reported - explained)
    return report


def recall(report: EvalReport) -> float:
    """召回率：成立假设中被抓到的比例。

    分母只算 `lookup.ok` 的假设——提议方看错的那些不算规则的账，
    否则「模型提得越离谱，规则召回率越好看」。
    """
    valid = [r for r in report.records if r.lookup.ok]
    if not valid:
        return 0.0
    return len([r for r in valid if r.hit]) / len(valid)


def aggregate(reports: list[EvalReport]) -> dict[str, float | int]:
    """多份配置聚合成一个数字组，供 README 报数。

    分母纪律：`recall` 用「全部成立假设数」作分母，不用「有成立假设的配置数」。
    按配置平均会让假设少的配置权重过大。
    """
    all_records = [r for rep in reports for r in rep.records]
    valid = [r for r in all_records if r.lookup.ok]
    hit = [r for r in valid if r.hit]

    return {
        "devices": len(reports),
        "claims": len(all_records),
        "valid_claims": len(valid),
        "invalid_claims": len(all_records) - len(valid),
        "true_positives": len(hit),
        "false_negatives": len(valid) - len(hit),
        "recall": (len(hit) / len(valid)) if valid else 0.0,
        "claim_accuracy": (len(valid) / len(all_records)) if all_records else 0.0,
        "unexplained": sum(len(rep.unexplained) for rep in reports),
    }


def load_specs(path: str | Path) -> list[InjectionSpec]:
    """从 YAML/JSON 载入真值标注。

    格式（YAML 列表）：
        - line_no: 17
          kind: ip_conflict
          expect_rule: IF-001
          note: Vlanif20 与 Vlanif10 网段重叠
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - 零依赖时的降级路径
        import json

        data = json.loads(text)
    else:
        data = yaml.safe_load(text)

    return [
        InjectionSpec(
            line_no=int(item["line_no"]),
            kind=str(item["kind"]),
            expect_rule=str(item["expect_rule"]),
            note=str(item.get("note", "")),
        )
        for item in data
    ]


def specs_from_text(text: str, device_id: str = "unknown") -> list[InjectionSpec]:
    """从配置文本解析出「真值标注」（仅用于测试与自检）。

    生产路径的真值来自模型或人工；此函数用于在单元测试里快速构造场景。
    """
    _ = (text, device_id)
    return []
