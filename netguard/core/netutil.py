"""IP / 掩码 / 反掩码相关的纯函数工具。

全部为无副作用的确定性计算，只依赖标准库 `ipaddress`。

设计原则（架构 P1：判定与表达分离）：
本模块只回答「是什么」——是不是合法地址、是否重叠、覆盖范围多大；
不回答「这是不是问题」——那是规则层的职责。
"""

from __future__ import annotations

import ipaddress

__all__ = [
    "is_ipv4",
    "ip_to_int",
    "int_to_ip",
    "is_contiguous_mask",
    "mask_to_prefix",
    "prefix_to_mask",
    "network_of",
    "same_subnet",
    "subnets_overlap",
    "ip_in_network",
    "is_valid_wildcard",
    "wildcard_covers",
    "wildcard_to_mask",
    "host_bits",
    "network_range",
    "cidr_of",
]

_ALL_ONES = 0xFFFFFFFF


def is_ipv4(text: str | None) -> bool:
    """判断字符串是否为合法 IPv4 点分十进制地址。"""
    if not text or not isinstance(text, str):
        return False
    try:
        ipaddress.IPv4Address(text)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def ip_to_int(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def is_contiguous_mask(mask: str | None) -> bool:
    """判断子网掩码是否为连续的 1（如 255.255.255.0）。

    255.0.255.0 这类非连续掩码在设备上虽然可配，但语义上不构成合法网段。
    """
    if not is_ipv4(mask):
        return False
    bits = bin(ip_to_int(mask))[2:].zfill(32)
    # 连续掩码形如 1*0*，不出现 "01"
    return "01" not in bits


def mask_to_prefix(mask: str) -> int:
    return bin(ip_to_int(mask)).count("1")


def prefix_to_mask(prefix: int) -> str:
    if not 0 <= prefix <= 32:
        raise ValueError(f"前缀长度必须在 0—32 之间，收到 {prefix}")
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def network_of(ip: str, mask: str) -> str:
    """返回 ip/mask 所在的网络地址。"""
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(net.network_address)


def cidr_of(ip: str, mask: str) -> str:
    """返回规范的 CIDR 表示，如 10.1.1.5/24 → 10.1.1.0/24。"""
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(net)


def network_range(ip: str, mask: str) -> tuple[int, int]:
    """返回 (网络地址整数, 广播地址整数)，闭区间。"""
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return int(net.network_address), int(net.broadcast_address)


def same_subnet(ip_a: str, mask_a: str, ip_b: str, mask_b: str) -> bool:
    """两个地址是否落入同一网段（任一方向重叠即算）。"""
    try:
        net_a = ipaddress.IPv4Network(f"{ip_a}/{mask_a}", strict=False)
        net_b = ipaddress.IPv4Network(f"{ip_b}/{mask_b}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False
    return net_a.overlaps(net_b)


def subnets_overlap(ip_a: str, mask_a: str, ip_b: str, mask_b: str) -> bool:
    """两个网段是否有交集。

    与 same_subnet 的区别：本函数要求两端都给出合法可解析的掩码，
    任一非法即返回 False，不做「尽量猜」的容错——规则层需要的是
    确定的判断，猜错会直接变成误报。
    """
    if not (is_ipv4(ip_a) and is_ipv4(ip_b)):
        return False
    if not (is_ipv4(mask_a) and is_ipv4(mask_b)):
        return False
    if not (is_contiguous_mask(mask_a) and is_contiguous_mask(mask_b)):
        return False
    a0, a1 = network_range(ip_a, mask_a)
    b0, b1 = network_range(ip_b, mask_b)
    return a0 <= b1 and b0 <= a1


def ip_in_network(ip: str, network: str, wildcard: str) -> bool:
    """OSPF network 命令语义：ip 是否落在 (network, wildcard) 描述的范围。

    wildcard 为反掩码，例如 0.0.0.255。注意 OSPF 的 network 命令
    按位与匹配，不要求 network 是规范网络地址。
    """
    if not (is_ipv4(ip) and is_ipv4(network) and is_ipv4(wildcard)):
        return False
    mask_int = _ALL_ONES ^ ip_to_int(wildcard)
    mask = int_to_ip(mask_int)
    try:
        net = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False
    return ipaddress.IPv4Address(ip) in net


def is_valid_wildcard(wildcard: str | None) -> bool:
    """反掩码合法性：必须是合法 IPv4，且取反后是连续掩码。"""
    if not is_ipv4(wildcard):
        return False
    mask_int = _ALL_ONES ^ ip_to_int(wildcard)
    return is_contiguous_mask(int_to_ip(mask_int))


def wildcard_to_mask(wildcard: str) -> str:
    """反掩码转正掩码。"""
    return int_to_ip(_ALL_ONES ^ ip_to_int(wildcard))


def wildcard_covers(wild_a: str, wild_b: str) -> bool:
    """判断反掩码 a 覆盖的范围是否包含反掩码 b 覆盖的范围。

    ACL 规则顺序分析用：前置规则的地址范围是否吞掉后置规则。
    反掩码中 1 越多，覆盖范围越大。
    """
    if not (is_valid_wildcard(wild_a) and is_valid_wildcard(wild_b)):
        return False
    return ip_to_int(wild_a) >= ip_to_int(wild_b)


def host_bits(wildcard: str) -> int:
    """反掩码中 1 的个数，即主机位数量。"""
    return bin(ip_to_int(wildcard)).count("1")
