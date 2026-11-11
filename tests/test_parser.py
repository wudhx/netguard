"""华为 VRP 解析器单元测试。

分四组：
1. VLAN 列表展开 —— 纯函数，边界最多
2. 结构解析 —— 缩进层级、块切换
3. undo 语义 —— 三种粒度
4. 反向用例 —— 不该被误解析的写法（防误报的关键）

反向用例优先：解析多认一条垃圾数据，比少认一条危险得多——
前者会变成规则的误报，后者只是覆盖率下降。
"""

from __future__ import annotations

import pytest

from netguard.core.parser import expand_vlan_list, parse


# ===========================================================================
# 1. VLAN 列表展开
# ===========================================================================


class TestExpandVlanList:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("10", [10]),
            ("10 20 30", [10, 20, 30]),
            ("10 20 30 to 35", [10, 20, 30, 31, 32, 33, 34, 35]),
            ("10 to 12", [10, 11, 12]),
            ("10 to 10", [10]),
            ("10,20,30", [10, 20, 30]),
            ("10 to 12 20", [10, 11, 12, 20]),
        ],
    )
    def test_normal(self, text: str, expected: list[int]) -> None:
        assert expand_vlan_list(text) == expected

    def test_reverse_range_sorted(self) -> None:
        """逆序区间按升序展开——设备侧合法，不应丢弃。"""
        assert expand_vlan_list("35 to 30") == [30, 31, 32, 33, 34, 35]

    def test_dedup_preserves_order(self) -> None:
        assert expand_vlan_list("10 20 10 30") == [10, 20, 30]

    def test_overlap_in_range(self) -> None:
        assert expand_vlan_list("5 to 8 8") == [5, 6, 7, 8]

    def test_dangling_to(self) -> None:
        """孤立 `to` 不产生任何数字，也不报错。"""
        assert expand_vlan_list("10 20 to") == [10, 20]
        assert expand_vlan_list("to 5") == [5]

    def test_empty(self) -> None:
        assert expand_vlan_list("") == []
        assert expand_vlan_list("   ") == []

    def test_garbage_ignored(self) -> None:
        """非数字 token 被跳过，不中断解析。"""
        assert expand_vlan_list("10 abc 20") == [10, 20]


# ===========================================================================
# 2. 结构解析
# ===========================================================================


class TestBasicStructure:
    def test_sysname(self) -> None:
        cfg = parse("sysname SW-01\n#\n")
        assert cfg.hostname == "SW-01"

    def test_sysname_fills_device_id(self) -> None:
        cfg = parse("sysname SW-01\n")
        assert cfg.device_id == "SW-01"

    def test_explicit_device_id_not_overwritten(self) -> None:
        cfg = parse("sysname SW-01\n", device_id="dev-42")
        assert cfg.device_id == "dev-42"
        assert cfg.hostname == "SW-01"

    def test_version(self) -> None:
        cfg = parse("version 5.170\n")
        assert cfg.version == "5.170"

    def test_crlf_and_cr(self) -> None:
        for text in ("sysname A\r\n#\r\n", "sysname A\r#\r"):
            cfg = parse(text)
            assert cfg.hostname == "A"

    def test_comment_lines_skipped(self) -> None:
        cfg = parse("! this is a comment\nsysname A\n")
        assert cfg.hostname == "A"

    def test_empty_input(self) -> None:
        cfg = parse("")
        assert cfg.interfaces == {}
        assert cfg.ospf == {}
        assert cfg.acls == {}


class TestInterface:
    def test_ip_and_mask(self) -> None:
        cfg = parse("interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n#\n")
        iface = cfg.interfaces["GE0/0/1"]
        assert (iface.ip, iface.mask) == ("10.1.1.1", "255.255.255.0")

    def test_description(self) -> None:
        cfg = parse("interface GE0/0/1\n description 上联口\n#\n")
        assert cfg.interfaces["GE0/0/1"].description == "上联口"

    def test_shutdown(self) -> None:
        cfg = parse("interface GE0/0/1\n shutdown\n#\n")
        assert cfg.interfaces["GE0/0/1"].admin_up is False

    def test_default_admin_up(self) -> None:
        cfg = parse("interface GE0/0/1\n description x\n#\n")
        assert cfg.interfaces["GE0/0/1"].admin_up is True

    def test_link_type_and_access_vlan(self) -> None:
        cfg = parse(
            "interface GE0/0/2\n port link-type access\n port default vlan 100\n#\n"
        )
        iface = cfg.interfaces["GE0/0/2"]
        assert iface.link_type == "access"
        assert iface.access_vlan == 100

    def test_trunk_allow_range(self) -> None:
        cfg = parse(
            "interface GE0/0/4\n port link-type trunk\n"
            " port trunk allow-pass vlan 10 20 30 to 32\n#\n"
        )
        assert cfg.interfaces["GE0/0/4"].trunk_allow == [10, 20, 30, 31, 32]

    def test_trunk_allow_all(self) -> None:
        cfg = parse(
            "interface GE0/0/4\n port trunk allow-pass vlan all\n#\n"
        )
        assert cfg.interfaces["GE0/0/4"].trunk_allow == [-1]

    def test_ospf_enable_in_interface(self) -> None:
        cfg = parse(
            "interface GE0/0/2\n ip address 10.1.1.1 255.255.255.252\n"
            " ospf enable 1 area 0.0.0.0\n#\n"
        )
        iface = cfg.interfaces["GE0/0/2"]
        assert iface.ospf_process == 1
        assert iface.ospf_area == "0.0.0.0"

    def test_traffic_filter_creates_binding(self) -> None:
        cfg = parse(
            "interface GE0/0/1\n traffic-filter inbound acl 3001\n#\n"
        )
        iface = cfg.interfaces["GE0/0/1"]
        assert iface.acl_in == "3001"
        assert len(cfg.acl_bindings) == 1
        b = cfg.acl_bindings[0]
        assert (b.interface, b.acl_number, b.direction) == ("GE0/0/1", "3001", "inbound")

    def test_traffic_filter_outbound(self) -> None:
        cfg = parse(
            "interface GE0/0/1\n traffic-filter outbound acl 3002\n#\n"
        )
        assert cfg.interfaces["GE0/0/1"].acl_out == "3002"

    def test_multiple_interfaces_do_not_mix(self) -> None:
        """关键回归：两个接口的配置不能串味。"""
        cfg = parse(
            "interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n#\n"
            "interface GE0/0/2\n ip address 10.2.2.2 255.255.255.0\n#\n"
        )
        assert cfg.interfaces["GE0/0/1"].ip == "10.1.1.1"
        assert cfg.interfaces["GE0/0/2"].ip == "10.2.2.2"

    def test_interface_reopened_merges(self) -> None:
        """同一接口分两段配置（VRP 导出常见），应合并而非覆盖。"""
        cfg = parse(
            "interface GE0/0/1\n description first\n#\n"
            "interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n#\n"
        )
        iface = cfg.interfaces["GE0/0/1"]
        assert iface.description == "first"
        assert iface.ip == "10.1.1.1"

    def test_line_no_recorded(self) -> None:
        cfg = parse("sysname A\n#\ninterface GE0/0/1\n ip address 1.1.1.1 255.0.0.0\n#\n")
        assert cfg.interfaces["GE0/0/1"].line_no == 3


class TestOspf:
    def test_process_id_and_router_id(self) -> None:
        cfg = parse("ospf 1 router-id 1.1.1.1\n#\n")
        assert cfg.ospf[1].router_id == "1.1.1.1"

    def test_router_id_separate_line(self) -> None:
        cfg = parse("ospf 1\n router-id 2.2.2.2\n#\n")
        assert cfg.ospf[1].router_id == "2.2.2.2"

    def test_multiple_areas(self) -> None:
        cfg = parse(
            "ospf 1\n"
            " area 0.0.0.0\n"
            "  network 10.1.1.0 0.0.0.255\n"
            " area 0.0.0.1\n"
            "  network 10.2.2.0 0.0.0.255\n"
            "#\n"
        )
        proc = cfg.ospf[1]
        assert set(proc.areas) == {"0.0.0.0", "0.0.0.1"}
        assert proc.areas["0.0.0.0"].networks == [("10.1.1.0", "0.0.0.255")]
        assert proc.areas["0.0.0.1"].networks == [("10.2.2.0", "0.0.0.255")]

    def test_network_stays_in_its_area(self) -> None:
        """关键回归：第二个 area 的 network 不能落进第一个 area。"""
        cfg = parse(
            "ospf 1\n"
            " area 0.0.0.0\n"
            "  network 10.1.1.0 0.0.0.255\n"
            "  network 10.1.2.0 0.0.0.255\n"
            " area 0.0.0.1\n"
            "  network 10.2.2.0 0.0.0.255\n"
            "#\n"
        )
        proc = cfg.ospf[1]
        assert len(proc.areas["0.0.0.0"].networks) == 2
        assert len(proc.areas["0.0.0.1"].networks) == 1

    def test_duplicate_network_deduped(self) -> None:
        cfg = parse(
            "ospf 1\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n"
            "  network 10.1.1.0 0.0.0.255\n#\n"
        )
        assert len(cfg.ospf[1].areas["0.0.0.0"].networks) == 1

    def test_multiple_processes(self) -> None:
        cfg = parse(
            "ospf 1\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n#\n"
            "ospf 2\n area 0.0.0.5\n  network 10.2.2.0 0.0.0.255\n#\n"
        )
        assert set(cfg.ospf) == {1, 2}
        assert cfg.ospf[1].areas["0.0.0.0"].networks[0][0] == "10.1.1.0"
        assert cfg.ospf[2].areas["0.0.0.5"].networks[0][0] == "10.2.2.0"


class TestAcl:
    def test_numbered_acl(self) -> None:
        cfg = parse("acl number 3001\n rule 5 deny ip\n#\n")
        assert "3001" in cfg.acls
        assert cfg.acls["3001"].rules[0].seq == 5

    def test_named_acl(self) -> None:
        cfg = parse("acl name MY_ACL\n rule 5 permit ip\n#\n")
        assert "MY_ACL" in cfg.acls

    def test_rule_with_source_wildcard(self) -> None:
        cfg = parse(
            "acl number 3001\n"
            " rule 5 deny ip source 10.1.1.0 0.0.0.255\n#\n"
        )
        r = cfg.acls["3001"].rules[0]
        assert (r.source, r.source_wildcard) == ("10.1.1.0", "0.0.0.255")

    def test_rule_with_destination(self) -> None:
        cfg = parse(
            "acl number 3001\n"
            " rule 5 deny tcp source 10.1.1.0 0.0.0.255"
            " destination 202.96.128.1 0.0.0.0 destination-port eq 80\n#\n"
        )
        r = cfg.acls["3001"].rules[0]
        assert r.protocol == "tcp"
        assert r.destination == "202.96.128.1"
        assert r.dst_port == "80"

    def test_rule_source_any(self) -> None:
        cfg = parse("acl number 3001\n rule 5 deny ip source any\n#\n")
        r = cfg.acls["3001"].rules[0]
        assert r.source is None

    def test_rule_no_source_means_any(self) -> None:
        cfg = parse("acl number 3001\n rule 30 permit ip\n#\n")
        r = cfg.acls["3001"].rules[0]
        assert r.source is None
        assert r.protocol == "ip"

    def test_rule_default_protocol(self) -> None:
        cfg = parse("acl number 2000\n rule 5 permit\n#\n")
        assert cfg.acls["2000"].rules[0].protocol == "ip"

    def test_empty_acl(self) -> None:
        cfg = parse("acl number 3003\n#\n")
        assert cfg.acls["3003"].is_empty() is True

    def test_deny_any_only(self) -> None:
        cfg = parse("acl number 3002\n rule 5 deny ip\n#\n")
        assert cfg.acls["3002"].only_deny_any() is True

    def test_rule_order_preserved(self) -> None:
        cfg = parse(
            "acl number 3001\n rule 30 permit ip\n rule 5 deny ip\n rule 10 deny ip\n#\n"
        )
        assert [r.seq for r in cfg.acls["3001"].rules] == [30, 5, 10]

    def test_rule_line_no(self) -> None:
        cfg = parse("acl number 3001\n rule 5 deny ip\n#\n")
        assert cfg.acls["3001"].rules[0].line_no == 2


class TestStaticRoute:
    def test_next_hop(self) -> None:
        cfg = parse("ip route-static 0.0.0.0 0.0.0.0 10.0.0.254\n")
        r = cfg.static_routes[0]
        assert (r.dest, r.mask, r.next_hop) == ("0.0.0.0", "0.0.0.0", "10.0.0.254")

    def test_interface_only(self) -> None:
        cfg = parse("ip route-static 192.168.0.0 255.255.255.0 GE0/0/2\n")
        r = cfg.static_routes[0]
        assert r.interface == "GE0/0/2"
        assert r.next_hop is None

    def test_preference_skipped(self) -> None:
        """`preference 60` 的 60 不能被当成出接口。"""
        cfg = parse(
            "ip route-static 172.16.0.0 255.255.0.0 10.10.10.2 preference 60\n"
        )
        r = cfg.static_routes[0]
        assert r.next_hop == "10.10.10.2"
        assert r.interface is None

    def test_incomplete_route_ignored(self) -> None:
        cfg = parse("ip route-static 10.0.0.0\n")
        assert cfg.static_routes == []

    def test_multiple_routes(self) -> None:
        cfg = parse(
            "ip route-static 0.0.0.0 0.0.0.0 1.1.1.1\n"
            "ip route-static 10.0.0.0 255.0.0.0 2.2.2.2\n"
        )
        assert len(cfg.static_routes) == 2


class TestGlobalSwitches:
    def test_telnet_enable(self) -> None:
        assert parse("telnet server enable\n").telnet_enabled is True

    def test_telnet_absent_is_false(self) -> None:
        assert parse("sysname A\n").telnet_enabled is False

    def test_snmp_read(self) -> None:
        cfg = parse("snmp-agent community read public\n")
        assert cfg.snmp_communities == ["public"]

    def test_snmp_write(self) -> None:
        cfg = parse("snmp-agent community write private\n")
        assert cfg.snmp_communities == ["private"]

    def test_snmp_cipher_marker_skipped(self) -> None:
        """关键回归：`cipher` 是加密标记，不是 community 名。"""
        cfg = parse("snmp-agent community read cipher %^%#abc123%^%#\n")
        assert cfg.snmp_communities == ["%^%#abc123%^%#"]

    def test_snmp_simple_marker_skipped(self) -> None:
        cfg = parse("snmp-agent community read simple public\n")
        assert cfg.snmp_communities == ["public"]

    def test_vlan_batch(self) -> None:
        cfg = parse("vlan batch 10 20 30 to 32\n")
        assert cfg.vlans == {10, 20, 30, 31, 32}

    def test_vlan_range_clamped(self) -> None:
        """超出 1—4094 的值应被丢弃。"""
        cfg = parse("vlan batch 4094 4095 0\n")
        assert cfg.vlans == {4094}

    def test_vrf_detected(self) -> None:
        assert parse("ip vpn-instance VPN_A\n").has_vrf is True
        assert parse("sysname A\n").has_vrf is False


# ===========================================================================
# 3. undo 语义
# ===========================================================================


class TestUndoSemantics:
    def test_undo_shutdown_restores_admin_up(self) -> None:
        cfg = parse("interface GE0/0/1\n shutdown\n undo shutdown\n#\n")
        assert cfg.interfaces["GE0/0/1"].admin_up is True

    def test_undo_ip_address_clears(self) -> None:
        cfg = parse(
            "interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n"
            " undo ip address\n#\n"
        )
        iface = cfg.interfaces["GE0/0/1"]
        assert iface.ip is None and iface.mask is None

    def test_undo_description_clears(self) -> None:
        cfg = parse("interface GE0/0/1\n description x\n undo description\n#\n")
        assert cfg.interfaces["GE0/0/1"].description is None

    def test_undo_telnet_disable(self) -> None:
        """`undo telnet server enable` 必须关掉，不能因 startswith 判成正向。"""
        assert parse("undo telnet server enable\n").telnet_enabled is False

    def test_undo_telnet_after_enable(self) -> None:
        cfg = parse("telnet server enable\nundo telnet server enable\n")
        assert cfg.telnet_enabled is False

    def test_undo_acl_removes_object(self) -> None:
        cfg = parse("acl number 3001\n rule 5 deny ip\n#\nundo acl number 3001\n")
        assert "3001" not in cfg.acls

    def test_undo_ospf_removes_process(self) -> None:
        cfg = parse("ospf 1\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n#\nundo ospf 1\n")
        assert cfg.ospf == {}

    def test_undo_rule_removes_by_seq(self) -> None:
        cfg = parse(
            "acl number 3001\n rule 5 deny ip\n rule 10 permit ip\n"
            " undo rule 5\n#\n"
        )
        assert [r.seq for r in cfg.acls["3001"].rules] == [10]

    def test_undo_network_removes_entry(self) -> None:
        cfg = parse(
            "ospf 1\n area 0.0.0.0\n  network 10.1.1.0 0.0.0.255\n"
            "  undo network 10.1.1.0 0.0.0.255\n#\n"
        )
        assert cfg.ospf[1].areas["0.0.0.0"].networks == []

    def test_undo_trunk_allow_clears(self) -> None:
        cfg = parse(
            "interface GE0/0/4\n port trunk allow-pass vlan 10 20\n"
            " undo port trunk allow-pass vlan 10 20\n#\n"
        )
        assert cfg.interfaces["GE0/0/4"].trunk_allow == []

    def test_undo_traffic_filter(self) -> None:
        cfg = parse(
            "interface GE0/0/1\n traffic-filter inbound acl 3001\n"
            " undo traffic-filter inbound\n#\n"
        )
        assert cfg.interfaces["GE0/0/1"].acl_in is None
        assert cfg.acl_bindings == []

    def test_undo_static_route(self) -> None:
        cfg = parse(
            "ip route-static 10.0.0.0 255.0.0.0 1.1.1.1\n"
            "undo ip route-static 10.0.0.0 255.0.0.0 1.1.1.1\n"
        )
        assert cfg.static_routes == []


# ===========================================================================
# 4. 反向用例：不该被误解析
# ===========================================================================


class TestNegativeCases:
    def test_indented_interface_not_treated_as_top_level(self) -> None:
        """缩进的 `interface` 字样不应创建新接口。"""
        cfg = parse(
            "interface GE0/0/1\n description interface test\n#\n"
        )
        assert list(cfg.interfaces) == ["GE0/0/1"]

    def test_description_not_parsed_as_command(self) -> None:
        """description 里的内容不能被当成配置命令。"""
        cfg = parse(
            "interface GE0/0/1\n description ip address 1.1.1.1 255.0.0.0\n#\n"
        )
        iface = cfg.interfaces["GE0/0/1"]
        assert iface.ip is None
        assert iface.description == "ip address 1.1.1.1 255.0.0.0"

    def test_network_outside_ospf_ignored(self) -> None:
        """不在 ospf 块内的 network 命令应被忽略。"""
        cfg = parse("network 10.1.1.0 0.0.0.255\n")
        assert cfg.ospf == {}

    def test_rule_outside_acl_ignored(self) -> None:
        cfg = parse("rule 5 deny ip\n")
        assert cfg.acls == {}

    def test_ip_address_outside_interface_ignored(self) -> None:
        cfg = parse("ip address 10.1.1.1 255.255.255.0\n")
        assert cfg.interfaces == {}

    def test_truncated_ip_address_line(self) -> None:
        """只有 IP 没有掩码：不解析，避免造出半条数据。"""
        cfg = parse("interface GE0/0/1\n ip address 10.1.1.1\n#\n")
        assert cfg.interfaces["GE0/0/1"].ip is None

    def test_garbage_lines_ignored(self) -> None:
        cfg = parse(
            "interface GE0/0/1\n"
            " ! random comment\n"
            " some unknown command with args\n"
            " ip address 10.1.1.1 255.255.255.0\n"
            "#\n"
        )
        assert cfg.interfaces["GE0/0/1"].ip == "10.1.1.1"

    def test_acls_do_not_merge(self) -> None:
        """两个 ACL 的规则不能混到一起。"""
        cfg = parse(
            "acl number 3001\n rule 5 deny ip\n#\n"
            "acl number 3002\n rule 10 permit ip\n#\n"
        )
        assert [r.seq for r in cfg.acls["3001"].rules] == [5]
        assert [r.seq for r in cfg.acls["3002"].rules] == [10]

    def test_no_cross_block_contamination(self) -> None:
        """接口块结束后，后续顶层命令不能落进接口。"""
        cfg = parse(
            "interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n#\n"
            "ospf 1\n router-id 9.9.9.9\n#\n"
        )
        assert cfg.interfaces["GE0/0/1"].description is None
        assert cfg.ospf[1].router_id == "9.9.9.9"

    def test_hash_terminates_block(self) -> None:
        """`#` 必须结束块，否则后续顶层命令会被误当成块内命令。"""
        cfg = parse(
            "interface GE0/0/1\n ip address 10.1.1.1 255.255.255.0\n#\n"
            "telnet server enable\n"
        )
        assert cfg.telnet_enabled is True


# ===========================================================================
# 5. 真实语料集成测试
# ===========================================================================


class TestCorpusIntegration:
    def test_case01_core_switch(self) -> None:
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "corpus" / "case01_core_switch.txt"
        if not path.exists():
            pytest.skip("corpus 文件不存在")
        cfg = parse(path.read_text(encoding="utf-8"))

        assert cfg.hostname == "SW-Core-01"
        assert cfg.vlans == {10, 20, 30}
        assert len(cfg.interfaces) == 4
        # Vlanif10 与 Vlanif20 网段重叠（故意植入的缺陷）
        assert cfg.interfaces["Vlanif10"].ip == "192.168.10.1"
        assert cfg.interfaces["Vlanif20"].ip == "192.168.10.2"
        # 同一网段被两个 Area 宣告（故意植入的缺陷）
        assert len(cfg.ospf[1].areas) == 2
        # ACL 前置 deny 覆盖后置 permit（故意植入的缺陷）
        rules = cfg.acls["3000"].rules
        assert rules[0].action == "deny"
        assert rules[1].action == "permit"
        assert cfg.telnet_enabled is True
        assert cfg.snmp_communities == ["public"]

    def test_case02_border_router(self) -> None:
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "corpus" / "case02_border_router.txt"
        if not path.exists():
            pytest.skip("corpus 文件不存在")
        cfg = parse(path.read_text(encoding="utf-8"))

        assert cfg.hostname == "ISP-BORDER-01"
        assert cfg.has_vrf is True
        assert 31 in cfg.vlans and 35 in cfg.vlans
        assert cfg.interfaces["GigabitEthernet0/0/3"].admin_up is False
        assert cfg.interfaces["GigabitEthernet0/0/2"].ospf_area == "0.0.0.0"
        assert cfg.interfaces["GigabitEthernet0/0/1"].acl_in == "3001"
        # 3003 是空 ACL
        assert cfg.acls["3003"].is_empty() is True
        # 3002 只有 deny any
        assert cfg.acls["3002"].only_deny_any() is True
        assert len(cfg.static_routes) == 3

    def test_case03_access_switch(self) -> None:
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "corpus" / "case03_access_switch.txt"
        if not path.exists():
            pytest.skip("corpus 文件不存在")
        cfg = parse(path.read_text(encoding="utf-8"))

        assert cfg.hostname == "EDGE-ACCESS-01"
        assert cfg.vlans == set(range(200, 211))
        assert cfg.telnet_enabled is False  # 被 undo 关掉了
        assert cfg.interfaces["GigabitEthernet0/0/1"].trunk_allow == list(range(200, 211))
        assert cfg.ospf[2].areas["0.0.0.5"].networks == [("172.20.1.0", "0.0.0.255")]
