"""IP / 掩码 / 网段相关的纯函数工具。

全部为无副作用的确定性计算，不依赖任何第三方库。
"""

from __future__ import annotations

import ipaddress


def is_ipv4(text: str) -> bool:
    """判断字符串是否为合法 IPv4 点分十进制地址。"""
    try:
        ipaddress.IPv4Address(text)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def ip_to_int(text: str) -> int:
    return int(ipaddress.IPv4Address(text))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def is_contiguous_mask(mask: str) -> bool:
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
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def network_of(ip: str, mask: str) -> str:
    """返回 ip/mask 所在的网络地址。"""
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(net.network_address)


def same_subnet(ip_a: str, mask_a: str, ip_b: str, mask_b: str) -> bool:
    """两个地址是否落入同一网段（按较窄的掩码比较，任一方向重叠即算）。"""
    try:
        net_a = ipaddress.IPv4Network(f"{ip_a}/{mask_a}", strict=False)
        net_b = ipaddress.IPv4Network(f"{ip_b}/{mask_b}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False
    return net_a.overlaps(net_b)


def ip_in_network(ip: str, network: str, wildcard: str) -> bool:
    """OSPF network 命令语义：ip 是否落在 (network, wildcard) 描述的范围。

    wildcard 为反掩码，例如 0.0.0.255。
    """
    if not (is_ipv4(ip) and is_ipv4(network) and is_ipv4(wildcard)):
        return False
    mask_int = 0xFFFFFFFF ^ ip_to_int(wildcard)
    mask = int_to_ip(mask_int)
    try:
        net = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False
    return ipaddress.IPv4Address(ip) in net


def is_valid_wildcard(wildcard: str) -> bool:
    """反掩码合法性：必须是合法 IPv4，且取反后是连续掩码。"""
    if not is_ipv4(wildcard):
        return False
    mask_int = 0xFFFFFFFF ^ ip_to_int(wildcard)
    return is_contiguous_mask(int_to_ip(mask_int))


def wildcard_covers(wild_a: str, wild_b: str) -> bool:
    """判断反掩码 a 覆盖的范围是否包含反掩码 b 覆盖的范围。

    ACL 规则顺序分析用：前置规则的地址范围是否吞掉后置规则。
    """
    if not (is_valid_wildcard(wild_a) and is_valid_wildcard(wild_b)):
        return False
    # 反掩码越大，覆盖范围越大
    return ip_to_int(wild_a) >= ip_to_int(wild_b)


def host_bits(wildcard: str) -> int:
    """反掩码中 1 的个数，即主机位数量。"""
    return bin(ip_to_int(wildcard)).count("1")
