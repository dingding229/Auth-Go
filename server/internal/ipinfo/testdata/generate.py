"""Generate tiny, synthetic MMDBs, without dependencies or downloaded data.
Run with Python 3; these records are test inventions, not real IP geography.
"""
from pathlib import Path
import ipaddress
import struct
HERE = Path(__file__).resolve().parent

def control(kind, size):
    if size < 29:
        length, extra = size, b''
    elif size < 285:
        length, extra = 29, bytes([size - 29])
    else:
        raise ValueError('fixture value too long')
    return bytes([(min(kind, 7) if kind < 8 else 0) << 5 | length]) + (bytes([kind - 7]) if kind >= 8 else b'') + extra

def encode(value):
    if isinstance(value, str):
        raw = value.encode('utf8')
        return control(2, len(raw)) + raw
    if isinstance(value, dict):
        return control(7, len(value)) + b''.join(encode(k) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return control(11, len(value)) + b''.join(encode(v) for v in value)
    kind, number = value
    raw = number.to_bytes(max(1, (number.bit_length() + 7) // 8), 'big')
    return control(kind, len(raw)) + raw

def make(filename, kind, records):
    tree = [None, None]
    for cidr, value in records:
        net = ipaddress.ip_network(cidr)
        bits = bin(int(net.network_address))[2:].zfill(net.max_prefixlen)[:net.prefixlen]
        if net.version == 4:
            bits = '0' * 96 + bits
        node = tree
        for bit in bits[:-1]:
            i = int(bit)
            if node[i] is None:
                node[i] = [None, None]
            node = node[i]
        node[int(bits[-1])] = value
    nodes = []
    def index(node):
        i = len(nodes)
        nodes.append(node)
        for n, child in enumerate(node):
            if isinstance(child, list):
                node[n] = ('node', index(child))
        return i
    index(tree)
    data = bytearray()
    search = bytearray()
    for node in nodes:
        for child in node:
            if child is None:
                pointer = len(nodes)
            elif isinstance(child, tuple):
                pointer = child[1]
            else:
                pointer = len(nodes) + 16 + len(data)
                data.extend(encode(child))
            search.extend(pointer.to_bytes(3, 'big'))
    metadata = {'binary_format_major_version': (5, 2), 'binary_format_minor_version': (5, 0),
                'build_epoch': (9, 1793480400), 'database_type': kind,
                'description': {'en': 'AuthGo synthetic test fixture'}, 'ip_version': (5, 6),
                'languages': ['en', 'zh-CN'], 'node_count': (6, len(nodes)), 'record_size': (5, 24)}
    (HERE / filename).write_bytes(search + bytes(16) + data + b'\xab\xcd\xefMaxMind.com' + encode(metadata))

city = {'country': {'iso_code': 'CN', 'names': {'en': 'China', 'zh-CN': '中国'}},
        'subdivisions': [{'names': {'en': 'Shanghai', 'zh-CN': '上海'}}], 'city': {'names': {'en': 'Shanghai', 'zh-CN': '上海'}}}
asn = {'autonomous_system_number': (6, 64500), 'autonomous_system_organization': 'Synthetic Network'}
make('city.mmdb', 'DBIP-City-Lite', [('8.8.8.0/24', city), ('2001:4860::/32', city)])
make('asn.mmdb', 'DBIP-ASN-Lite', [('8.8.8.0/24', asn), ('2001:4860::/32', asn)])
make('city-other.mmdb', 'GeoLite2-City', [('8.8.8.0/24', {'country': {'iso_code': 'US', 'names': {'en': 'United States'}}})])
make('asn-traits.mmdb', 'GeoIP2-ISP', [('8.8.8.0/24', {'traits': asn})])
