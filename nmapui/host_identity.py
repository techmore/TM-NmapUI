"""Bounded direct-device mDNS identity lookup; no authentication required."""
import ipaddress
import socket
import struct


def _name(data, offset):
    labels, visited, end = [], set(), None
    for _ in range(128):
        if offset in visited or offset >= len(data):
            raise ValueError("Invalid DNS name")
        visited.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError("Invalid DNS label")
        offset += 1
        if not length:
            return ".".join(labels), end if end is not None else offset
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    raise ValueError("DNS name too long")


def query_mdns_hostname(address, timeout=1.0):
    """Ask one private IPv4 device for its own reverse name using unicast mDNS.

    A reply is device-reported identity, not directory verification. Silence is
    inconclusive and must never change the device's online/offline status.
    """
    try:
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return None
        owner = ip.reverse_pointer
        question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in owner.split(".")) + b"\0"
        packet = struct.pack("!6H", 0, 0, 1, 0, 0, 0) + question + struct.pack("!HH", 12, 0x8001)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.sendto(packet, (str(ip), 5353))
            data, peer = client.recvfrom(8192)
        if peer[0] != str(ip) or peer[1] != 5353 or len(data) < 12:
            return None
        _, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
        if not flags & 0x8000 or flags & 0x000F or questions > 32 or answers > 128:
            return None
        offset = 12
        for _ in range(questions):
            _, offset = _name(data, offset)
            offset += 4
        for _ in range(answers):
            record_owner, offset = _name(data, offset)
            kind, record_class, _, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if offset + length > len(data):
                return None
            if kind == 12 and record_class & 0x7FFF == 1 and record_owner.lower() == owner:
                hostname, end = _name(data, offset)
                labels = hostname.rstrip(".").split(".")
                if end <= offset + length and len(hostname) <= 253 and all(
                    0 < len(label) <= 63 and all(c.isalnum() or c == "-" or c == "_" for c in label)
                    for label in labels
                ):
                    return {"hostname": hostname, "hostname_source": "device_mdns"}
            offset += length
    except (OSError, ValueError, UnicodeError, struct.error):
        return None
    return None
