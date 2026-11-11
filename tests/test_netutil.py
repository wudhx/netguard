"""netutil 单元测试。

重点覆盖三类易错点：
1. 非连续掩码（255.0.255.0）——设备可配但语义非法
2. 反掩码与正掩码的互转、覆盖关系（ACL 顺序分析依赖）
3. 网段重叠的对称性与边界（相邻网段不算重叠）
"""

from __future__ import annotations

import pytest

from netguard.core import netutil as nu


class TestIsIpv4:
    @pytest.mark.parametrize("text", ["0.0.0.0", "255.255.255.255", "10.1.1.1", "192.168.0.1"])
    def test_valid(self, text: str) -> None:
        assert nu.is_ipv4(text) is True

    @pytest.mark.parametrize(
        "text",
        ["", None, "10.1.1", "10.1.1.256", "10.1.1.1.1", "abc", "10.1.1.-1", " 10.1.1.1", "10.1.1.1 "],
    )
    def test_invalid(self, text) -> None:
        assert nu.is_ipv4(text) is False


class TestContiguousMask:
    @pytest.mark.parametrize(
        "mask",
        ["0.0.0.0", "255.0.0.0", "255.255.0.0", "255.255.255.0", "255.255.255.128",
         "255.255.255.252", "255.255.255.255"],
    )
    def test_contiguous(self, mask: str) -> None:
        assert nu.is_contiguous_mask(mask) is True

    @pytest.mark.parametrize(
        "mask",
        ["255.0.255.0", "0.255.0.0", "255.255.0.255", "255.255.255.1", "0.0.0.255"],
    )
    def test_non_contiguous(self, mask: str) -> None:
        assert nu.is_contiguous_mask(mask) is False

    def test_invalid_string_is_false(self) -> None:
        assert nu.is_contiguous_mask("not-a-mask") is False


class TestPrefixMaskRoundTrip:
    @pytest.mark.parametrize("prefix", range(0, 33))
    def test_round_trip(self, prefix: int) -> None:
        mask = nu.prefix_to_mask(prefix)
        assert nu.mask_to_prefix(mask) == prefix
        assert nu.is_contiguous_mask(mask) is True

    def test_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            nu.prefix_to_mask(33)
        with pytest.raises(ValueError):
            nu.prefix_to_mask(-1)


class TestNetworkOf:
    def test_truncates_host_bits(self) -> None:
        assert nu.network_of("10.1.1.5", "255.255.255.0") == "10.1.1.0"

    def test_slash_30(self) -> None:
        assert nu.network_of("192.168.1.7", "255.255.255.252") == "192.168.1.4"

    def test_cidr_of(self) -> None:
        assert nu.cidr_of("10.1.1.5", "255.255.255.0") == "10.1.1.0/24"


class TestSubnetOverlap:
    def test_same_subnet(self) -> None:
        assert nu.subnets_overlap("10.1.1.1", "255.255.255.0", "10.1.1.200", "255.255.255.0") is True

    def test_contained(self) -> None:
        # /24 被 /16 包含
        assert nu.subnets_overlap("10.1.1.0", "255.255.255.0", "10.1.0.0", "255.255.0.0") is True

    def test_adjacent_not_overlap(self) -> None:
        # 10.1.1.0/24 与 10.1.2.0/24 相邻但不重叠
        assert nu.subnets_overlap("10.1.1.0", "255.255.255.0", "10.1.2.0", "255.255.255.0") is False

    def test_different_class(self) -> None:
        assert nu.subnets_overlap("10.0.0.0", "255.0.0.0", "192.168.0.0", "255.255.0.0") is False

    def test_symmetric(self) -> None:
        a = nu.subnets_overlap("10.1.1.0", "255.255.255.0", "10.1.0.0", "255.255.0.0")
        b = nu.subnets_overlap("10.1.0.0", "255.255.0.0", "10.1.1.0", "255.255.255.0")
        assert a == b is True

    def test_non_contiguous_mask_returns_false(self) -> None:
        # 非连续掩码不猜，直接判不重叠，避免误报
        assert nu.subnets_overlap("10.1.1.0", "255.0.255.0", "10.1.1.0", "255.0.255.0") is False

    def test_invalid_ip_returns_false(self) -> None:
        assert nu.subnets_overlap("bad", "255.255.255.0", "10.1.1.0", "255.255.255.0") is False


class TestIpInNetwork:
    def test_ospf_typical(self) -> None:
        assert nu.ip_in_network("10.1.1.1", "10.1.1.0", "0.0.0.255") is True

    def test_outside(self) -> None:
        assert nu.ip_in_network("10.1.2.1", "10.1.1.0", "0.0.0.255") is False

    def test_host_wildcard(self) -> None:
        assert nu.ip_in_network("10.1.1.1", "10.1.1.1", "0.0.0.0") is True
        assert nu.ip_in_network("10.1.1.2", "10.1.1.1", "0.0.0.0") is False

    def test_any(self) -> None:
        assert nu.ip_in_network("8.8.8.8", "0.0.0.0", "255.255.255.255") is True

    def test_non_canonical_network(self) -> None:
        # OSPF network 命令按位与匹配，不要求规范网络地址
        assert nu.ip_in_network("10.1.1.5", "10.1.1.1", "0.0.0.255") is True

    def test_invalid_input(self) -> None:
        assert nu.ip_in_network("x", "10.1.1.0", "0.0.0.255") is False


class TestWildcard:
    @pytest.mark.parametrize(
        "wild", ["0.0.0.0", "0.0.0.255", "0.0.255.255", "0.255.255.255", "255.255.255.255"]
    )
    def test_valid(self, wild: str) -> None:
        assert nu.is_valid_wildcard(wild) is True

    @pytest.mark.parametrize("wild", ["0.0.255.0", "255.0.255.0", "0.255.0.255"])
    def test_invalid(self, wild: str) -> None:
        assert nu.is_valid_wildcard(wild) is False

    def test_wildcard_to_mask(self) -> None:
        assert nu.wildcard_to_mask("0.0.0.255") == "255.255.255.0"
        assert nu.wildcard_to_mask("0.0.0.0") == "255.255.255.255"

    def test_covers(self) -> None:
        # /24 的反掩码比 /32 大，覆盖范围更大
        assert nu.wildcard_covers("0.0.0.255", "0.0.0.0") is True
        assert nu.wildcard_covers("0.0.0.0", "0.0.0.255") is False

    def test_covers_invalid(self) -> None:
        assert nu.wildcard_covers("bad", "0.0.0.0") is False

    def test_host_bits(self) -> None:
        assert nu.host_bits("0.0.0.255") == 8
        assert nu.host_bits("0.0.0.0") == 0
        assert nu.host_bits("255.255.255.255") == 32


class TestNetworkRange:
    def test_slash_24(self) -> None:
        lo, hi = nu.network_range("10.1.1.0", "255.255.255.0")
        assert nu.int_to_ip(lo) == "10.1.1.0"
        assert nu.int_to_ip(hi) == "10.1.1.255"

    def test_slash_30(self) -> None:
        lo, hi = nu.network_range("10.1.1.5", "255.255.255.252")
        assert nu.int_to_ip(lo) == "10.1.1.4"
        assert nu.int_to_ip(hi) == "10.1.1.7"
