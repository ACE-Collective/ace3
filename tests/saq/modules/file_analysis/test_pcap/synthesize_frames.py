#!/usr/bin/env python3
"""Writes network.pcap: hand-built ethernet/udp frames for the protocols a loopback capture cannot
produce (real MAC addresses, DNS, DHCP, NBNS). Every name, address and MAC is synthetic.
Run by generate_fixtures.sh."""

import socket
import struct
import sys

CLIENT_MAC = bytes.fromhex("020000aa0001")
SERVER_MAC = bytes.fromhex("020000bb0002")
BROADCAST_MAC = b"\xff" * 6
CLIENT_IP = "10.20.30.40"
RESOLVER_IP = "10.20.30.1"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_frame(src_mac: bytes, dst_mac: bytes, src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return dst_mac + src_mac + b"\x08\x00" + header + udp


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(txid: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid: int, name: str, cname: str, address: str) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    cname_rr = dns_name(name) + struct.pack("!HHIH", 5, 1, 300, len(dns_name(cname))) + dns_name(cname)
    a_rr = dns_name(cname) + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(address)
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 2, 0, 0) + question + cname_rr + a_rr


def dhcp_request(hostname: str) -> bytes:
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x12345678, 0, 0x8000,
                         b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
                         CLIENT_MAC + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
    options = b"\x63\x82\x53\x63"
    options += b"\x35\x01\x03"
    options += b"\x32\x04" + socket.inet_aton(CLIENT_IP)
    options += b"\x0c" + bytes([len(hostname)]) + hostname.encode()
    options += b"\xff"
    return header + options


def nbns_name(name: str) -> bytes:
    padded = name.upper().ljust(15)[:15] + "\x00"
    encoded = "".join(chr(0x41 + (ord(c) >> 4)) + chr(0x41 + (ord(c) & 0x0F)) for c in padded)
    return bytes([32]) + encoded.encode() + b"\x00"


def nbns_registration(name: str) -> bytes:
    question = nbns_name(name) + struct.pack("!HH", 0x20, 1)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 0x20, 1, 300000, 6) + b"\x00\x00" + socket.inet_aton(CLIENT_IP)
    return struct.pack("!HHHHHH", 0x4242, 0x2910, 1, 0, 0, 1) + question + rr


def frames() -> list[bytes]:
    return [
        udp_frame(CLIENT_MAC, BROADCAST_MAC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_request("pcap-workstation")),
        udp_frame(CLIENT_MAC, BROADCAST_MAC, CLIENT_IP, "10.20.30.255", 137, 137, nbns_registration("PCAPNBNSHOST")),
        udp_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, RESOLVER_IP, 53001, 53, dns_query(0x1111, "www.pcap-dns.example")),
        udp_frame(SERVER_MAC, CLIENT_MAC, RESOLVER_IP, CLIENT_IP, 53, 53001,
                  dns_response(0x1111, "www.pcap-dns.example", "cdn.pcap-dns.example", "198.51.100.7")),
        udp_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, RESOLVER_IP, 53002, 53, dns_query(0x2222, "7.100.51.198.in-addr.arpa")),
    ]


def write_pcap(path: str):
    with open(path, "wb") as fp:
        fp.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames()):
            fp.write(struct.pack("<IIII", 1767225600 + index, 0, len(frame), len(frame)))
            fp.write(frame)


if __name__ == "__main__":
    write_pcap(sys.argv[1])
