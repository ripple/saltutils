#!/usr/bin/python

"""
Quick and dirty dependency-less script to pick a network interface.

Salt Stack has an obtuse grains data structure for picking the first
network interface with an IPv4 RFC1918 address.  This script should
hopefully address this by simply returning the first compliant one.

Based on https://gist.github.com/provegard/1536682, which was
Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
Only tested on Linux!
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes
import ctypes.util
import logging
import sys
from socket import AF_INET, AF_INET6, inet_ntop

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)
log_formatter = logging.Formatter(('%(asctime)s - %(name)s - %(levelname)s'
                                   ' - %(message)s'))
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.CRITICAL)
logger.addHandler(log_handler)

RFC1918_NETWORKS = (
    '192.168.0.0/16',
    '172.16.0.0/12',
    '10.0.0.0/8',
)

#TODO(dmw) Add glob support for specifying blacklisted interfaces.
INT_BLACKLIST = ('lo', 'docker0', 'tun0', 'tun1')


class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14),]


class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', c_ushort),
        ('sin_port', c_uint16),
        ('sin_addr', c_byte * 4)]


class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_byte * 16),
        ('sin6_scope_id', c_uint32)]


class union_ifa_ifu(Union):
    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr)),]


class struct_ifaddrs(Structure):
    pass


struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]


libc = ctypes.CDLL(ctypes.util.find_library('c'))


def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents


def getfamaddr(sa):
    family = sa.sa_family
    addr = None
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sa.sin6_addr)
    return family, addr


class NetworkInterface(object):
    def __init__(self, name):
        self.name = name
        self.index = libc.if_nametoindex(name)
        self.addresses = {}

    def __str__(self):
        return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
            self.name, self.index,
            self.addresses.get(AF_INET),
            self.addresses.get(AF_INET6))


def get_network_interfaces():
    ifap = POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(pointer(ifap))
    if result != 0:
        raise OSError(get_errno())
    del result
    try:
        retval = {}
        for ifa in ifap_iter(ifap):
            name = ifa.ifa_name.decode("UTF-8")
            i = retval.get(name)
            if not i:
                i = retval[name] = NetworkInterface(name)
            if not ifa.ifa_addr:
                # skip null ifa_addr pointers
                continue
            family, addr = getfamaddr(ifa.ifa_addr.contents)
            if addr:
                if family not in i.addresses:
                    i.addresses[family] = list()
                i.addresses[family].append(addr)
        return retval.values()
    finally:
        libc.freeifaddrs(ifap)


class IPv4Address(object):

    def __init__(self, address):
        self.cidr = address
        self.octets = []
        self.address = c_uint32(0)
        self.netmask = c_uint32((2**32) - 1)

    def build_address(self):
        address = c_uint32(self.octets[0])
        for octet in self.octets[1:]:
            address.value <<= 8
            address.value |= octet
        self.address = address

    def parse(self):
        self.octets = [int(o) for o in self.cidr.split('.')]
        self.build_address()


class IPv4Network(IPv4Address):
    """

    mini invariants aka tests
    - mask shifted complement of provided bits is 0
    - mask AND'ed with base address == base address
    - given known host ip and mask, get expected network addr
    """

    def __init__(self, cidr):
        self.cidr = cidr
        self.octets = []
        self.num_masked_bits = 0
        self.address = c_uint32(0)
        self.netmask = c_uint32(0)
        self.broadcast = c_uint32(0)

    def build_netmask(self):
        mask = c_uint32((2**32) - 1)
        host_bits = 32 - self.num_masked_bits
        mask.value <<= host_bits
        self.netmask = mask

    def build_top(self):
        host_mask = ~self.netmask.value
        broadcast_ip = self.address.value | host_mask
        self.broadcast = c_uint32(broadcast_ip)

    def parse(self):
        ip_net, mask = self.cidr.split('/', 1)
        self.num_masked_bits = int(mask)
        self.octets = [int(o) for o in ip_net.split('.')]
        self.build_address()
        self.build_netmask()
        self.build_top()

    def address_in(self, ip):
        bottom = self.address.value
        top = self.broadcast.value
        if isinstance(ip, c_uint32):
            target = ip.value
        elif isinstance(ip, IPv4Address):
            target = ip.address.value
        elif isinstance(ip, (str, unicode)):
            addr = IPv4Address(ip)
            addr.parse()
            target = addr.address.value
        else:
            target = ip
        return bottom <= target <= top


def main(_):
    """Find a network interface with a RFC1918 address."""
    candidates = []
    for interface in get_network_interfaces():
        if interface.name in INT_BLACKLIST:
            continue
        ipv4_addresses = interface.addresses.get(AF_INET)
        for addr in ipv4_addresses:
            logger.debug('Raw ipv4: {}'.format(addr))
            ipv4 = IPv4Address(addr)
            ipv4.parse()
            logger.debug('IPv4 address: {}'.format(ipv4.address))
            for internal_net in RFC1918_NETWORKS:
                network = IPv4Network(internal_net)
                network.parse()
                logger.debug('IPv4 Network: {}'.format(network.address))
                logger.debug('IPv4 Broadcast: {}'.format(network.broadcast))
                logger.debug('IPv4 Netmask: {}'.format(network.netmask))
                if network.address_in(ipv4):
                    candidates.append(interface.name)

    num_candidates = len(candidates)
    if num_candidates < 1:
        logger.warning(
            "WARNING: No RFC1918 interfaces found! Returning loopback.\n"
        )
        return "lo"
    elif num_candidates == 1:
        return candidates[0]
    else:
        candidates.sort()
        logger.warning(
            "WARNING: >1 interface ('{}') found! Returning {}.\n".format(
                ', '.join(candidates), candidates[0])
        )
        return candidates[0]


if __name__ == '__main__':
    print(main(sys.argv[1:]))
