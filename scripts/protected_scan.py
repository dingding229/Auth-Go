#!/usr/bin/env python3
"""payload test-only plaintext evidence. No code from this module enters release images.

Scans current linked files, not process memory, deleted/open files or historical
blocks. The live check brackets all reads with the same running container PID.
Docker export is supplemented with its overlay upperdir and every storage-backed
writable mount; mounts are deliberately NOT assumed to be part of export.
"""
import bz2
import gzip
import io
import json
import lzma
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import zipfile

MARKER = b'AUTHGO_payload_PROTECTED_CORE'
MARKERS = (MARKER, MARKER.decode().encode('utf-16le'), MARKER.decode().encode('utf-16be'))
MAX_BYTES = 2 * 1024**3
MAX_FILES = 200000


class Leak(AssertionError):
    pass


def marker_check(data):
    if any(marker in data for marker in MARKERS):
        raise Leak('plaintext marker detected')


class PrefixReader(io.RawIOBase):
    def __init__(self, prefix, source):
        self.prefix, self.source = prefix, source

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.prefix:
            n = min(len(buffer), len(self.prefix))
            buffer[:n], self.prefix = self.prefix[:n], self.prefix[n:]
            return n
        data = self.source.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)


class CheckedReader(io.RawIOBase):
    """Check every consumed archive byte too, including headers and trailing data."""
    def __init__(self, source, scanner):
        self.source, self.scanner, self.tail = source, scanner, b''

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.source.read(len(buffer))
        self.scanner.count(data)
        marker_check(self.tail + data)
        self.tail = (self.tail + data)[-max(map(len, MARKERS)):]
        buffer[:len(data)] = data
        return len(data)


class Scanner:
    def __init__(self):
        self.bytes = self.files = 0
        self.formats = {}
        self.entries = {}
        self.metadata = {}

    def count(self, data):
        self.bytes += len(data)
        assert self.bytes <= MAX_BYTES, 'scan expanded-byte limit exceeded'

    def content(self, source, name='', depth=0):
        assert depth <= 8, 'scan archive nesting limit exceeded'
        self.files += 1
        assert self.files <= MAX_FILES, 'scan entry limit exceeded'
        prefix = source.read(512)
        stream = io.BufferedReader(CheckedReader(io.BufferedReader(PrefixReader(prefix, source)), self))

        def finish(kind):
            # tar readers may stop at the first end-of-archive block; scan any
            # remaining bytes rather than silently ignoring an appended marker.
            while stream.read(1024 * 1024):
                pass
            return kind
        # Unsupported compressed layers must fail, never be treated as opaque data.
        assert not prefix.startswith((b'\x28\xb5\x2f\xfd', b'\x04\x22\x4d\x18')), 'unsupported zstd/lz4 compression'
        if len(prefix) >= 4:
            assert not 0x184D2A50 <= int.from_bytes(prefix[:4], 'little') <= 0x184D2A5F, 'unsupported skippable compressed frame'
        codec = None
        if prefix.startswith(b'\x1f\x8b'):
            codec, opener = 'gzip', gzip.GzipFile
        elif prefix.startswith(b'BZh'):
            codec, opener = 'bzip2', bz2.BZ2File
        elif prefix.startswith(b'\xfd7zXZ\x00'):
            codec, opener = 'xz', lzma.LZMAFile
        if codec:
            self.formats[codec] = self.formats.get(codec, 0) + 1
            inner = opener(fileobj=stream) if codec == 'gzip' else opener(stream)
            with inner:
                kind = self.content(inner, name.removesuffix('.gz').removesuffix('.xz').removesuffix('.bz2'), depth + 1)
            return finish(kind)
        if prefix[:4] in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
            self.formats['zip'] = self.formats.get('zip', 0) + 1
            data = stream.read(64 * 1024**2 + 1)
            assert len(data) <= 64 * 1024**2, 'scan zip materialization limit exceeded'
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    marker_check(member.filename.encode())
                    assert not member.flag_bits & 1, 'encrypted zip is not scannable'
                    if not member.is_dir():
                        with archive.open(member) as inner:
                            self.content(inner, member.filename, depth + 1)
            return finish('zip')
        if name.endswith('.tar') or (len(prefix) == 512 and (prefix[257:262] == b'ustar' or name.startswith('blobs/sha256/') and prefix == bytes(512))):
            self.formats['tar'] = self.formats.get('tar', 0) + 1
            try:
                with tarfile.open(fileobj=stream, mode='r|') as archive:
                    for member in archive:
                        marker_check((member.name + '\n' + member.linkname).encode())
                        if member.isfile():
                            with archive.extractfile(member) as inner:
                                kind = self.content(inner, member.name, depth + 1)
                            if depth == 0:
                                self.entries[member.name.removeprefix('./')] = kind
            except tarfile.TarError as error:
                raise AssertionError('invalid tar entry: ' + repr(name)) from error
            return finish('tar')
        capture = depth == 1 and (name in ('manifest.json', 'index.json', 'oci-layout') or name.startswith('blobs/') and prefix.lstrip().startswith(b'{'))
        data = bytearray()
        while block := stream.read(1024 * 1024):
            if capture:
                data.extend(block)
                assert len(data) <= 4 * 1024**2, 'scan manifest size limit exceeded'
        if capture:
            self.metadata[name] = json.loads(data)
        return 'raw'

    def summary(self):
        return {'entries': self.files, 'scanned_bytes_with_archive_wrappers': self.bytes, 'formats': self.formats}

    def saved_image(self):
        layers, attestations = set(), set()
        formats = []
        if 'manifest.json' in self.metadata:
            manifests = self.metadata['manifest.json']
            assert isinstance(manifests, list) and manifests, 'missing docker-save manifests'
            for manifest in manifests:
                assert manifest.get('Layers'), 'missing docker-save layers'
                layers.update(manifest['Layers'])
            formats.append('docker-save manifest.json')
        if 'index.json' in self.metadata:
            assert self.metadata.get('oci-layout', {}).get('imageLayoutVersion') == '1.0.0', 'unknown OCI layout'
            supported = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar+zstd', 'application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.docker.image.rootfs.diff.tar.gzip'}
            visited = set()

            def walk(obj):
                for desc in obj.get('layers', []):
                    if desc['mediaType'] == 'application/vnd.in-toto+json':
                        attestations.add(blob(desc))
                        continue
                    assert desc['mediaType'] in supported, 'unsupported OCI layer media type: ' + desc['mediaType']
                    assert not desc['mediaType'].endswith('+zstd'), 'unsupported zstd OCI layer'
                    layers.add(blob(desc))
                for desc in obj.get('manifests', []):
                    path = blob(desc)
                    assert path in self.metadata, 'missing OCI manifest blob'
                    if path not in visited:
                        visited.add(path)
                        walk(self.metadata[path])

            def blob(desc):
                assert re.fullmatch(r'sha256:[0-9a-f]{64}', desc['digest']), 'unexpected OCI digest'
                return 'blobs/sha256/' + desc['digest'].split(':')[1]

            walk(self.metadata['index.json'])
            formats.append('OCI image-layout 1.0.0')
        assert formats and layers, 'unrecognized docker save archive'
        assert all(self.entries.get(path) == 'tar' for path in layers), 'missing or unscanned image layer'
        assert all(path in self.entries for path in attestations), 'missing attestation blob'
        return {**self.summary(), 'export_format': formats, 'verified_layers': len(layers), 'scanned_attestations': len(attestations)}


def docker_scan(args):
    scanner = Scanner()
    process = subprocess.Popen(['docker', *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        scanner.content(process.stdout, 'docker.tar')
        # Drain trailing tar padding; docker must finish successfully.
        while block := process.stdout.read(1024 * 1024):
            scanner.count(block)
            marker_check(block)
        assert process.wait(timeout=10) == 0, 'docker archive export failed'
        return scanner.saved_image() if args[0] == 'save' else scanner.summary()
    except BaseException:
        # Docker's Go CLI can trap SIGTERM while blocked writing this pipe.
        # Close the reader first and bound cleanup so a rejected archive cannot hang.
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        raise
    finally:
        process.stdout.close()


def scan_fd(fd, scanner, depth=0):
    """Never follow a symlink, block on a FIFO, or descend into a device."""
    assert depth <= 128, 'scan directory depth limit exceeded'
    for item in os.scandir(fd):
        scanner.files += 1
        assert scanner.files <= MAX_FILES, 'scan filesystem entry limit exceeded'
        marker_check(item.name.encode())
        info = item.stat(follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                scan_fd(child, scanner, depth + 1)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            child = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(child, 'rb') as source:
                assert stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'file changed kind during scan'
                scanner.content(source, item.name)
        # Links and special devices are not plaintext storage; never follow them.


def scan_tree(path):
    scanner = Scanner()
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        scan_fd(fd, scanner)
    finally:
        os.close(fd)
    return scanner.summary()


def unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def live_scan(name, volume, inspect):
    assert name.startswith('authgo-') and volume.startswith('authgo-'), 'refusing unowned scan'
    cfg = inspect(name)
    assert cfg['Name'] == '/' + name and cfg['State']['Running'], 'container not running'
    pid = cfg['State']['Pid']
    identity = (cfg['Id'], pid, cfg['State']['StartedAt'])
    assert pid > 1, 'invalid container PID'
    proc = pathlib.Path('/proc') / str(pid)
    mounts = []
    for line in (proc / 'mountinfo').read_text().splitlines():
        first, last = line.split(' - ', 1)
        fields, tail = first.split(), last.split()
        mounts.append({'path': unescape(fields[4]), 'rw': 'rw' in fields[5].split(','), 'type': tail[0], 'super': tail[2]})
    root = next(x for x in mounts if x['path'] == '/')
    upper = next((unescape(x[9:]) for x in root['super'].split(',') if x.startswith('upperdir=')), None)
    assert root['type'] == 'overlay' and upper, 'overlay upperdir unavailable: cannot certify writable layer'
    expected = [m for m in cfg['Mounts'] if m['Destination'] == '/var/lib/authgo']
    assert len(expected) == 1 and expected[0]['Type'] == 'volume' and expected[0]['Name'] == volume, 'unexpected cache volume'
    result = {'pid': pid, 'cache_volume': scan_tree(expected[0]['Source']), 'writable_upperdir': scan_tree(upper), 'live_export': docker_scan(['export', name]), 'tmpfs': {}, 'writable_bind_files': [], 'masked_kernel_null_devices': []}
    # Docker always adds /dev tmpfs and /dev/shm, even without --tmpfs /tmp.
    rootfd = os.open(proc / 'root', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for mount in mounts:
            if not mount['rw'] or mount['path'] == '/':
                continue
            path = mount['path']
            if mount['type'] in ('proc', 'sysfs', 'cgroup', 'cgroup2', 'devpts', 'mqueue'):
                continue  # kernel pseudo-files, not a writable storage filesystem
            if path == '/var/lib/authgo':
                continue  # independently verified named volume above
            assert mount['type'] == 'tmpfs' or path in ('/etc/hostname', '/etc/hosts', '/etc/resolv.conf'), 'unexpected writable mount: ' + path
            # Open each component without following any container-controlled link.
            fd = os.dup(rootfd)
            try:
                for component in pathlib.PurePosixPath(path).parts[1:]:
                    child = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    os.close(fd)
                    fd = child
                scanner = Scanner()
                if mount['type'] == 'tmpfs':
                    info = os.fstat(fd)
                    if stat.S_ISDIR(info.st_mode):
                        scan_fd(fd, scanner)
                    elif stat.S_ISREG(info.st_mode):
                        with os.fdopen(os.dup(fd), 'rb') as source:
                            scanner.content(source, path)
                    else:
                        # Docker masks these kernel pseudo-files with /dev/null.
                        assert path in ('/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list', '/proc/sched_debug') and stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3), 'unexpected tmpfs special mount'
                        result['masked_kernel_null_devices'].append(path)
                        continue
                    result['tmpfs'][path] = scanner.summary()
                else:
                    with os.fdopen(os.dup(fd), 'rb') as source:
                        scanner.content(source, path)
                    result['writable_bind_files'].append(path)
            finally:
                os.close(fd)
    finally:
        os.close(rootfd)
    assert '/tmp' in result['tmpfs'] and '/dev/shm' in result['tmpfs'], 'required tmpfs not inspected'
    after = inspect(name)
    assert after['State']['Running'] and (after['Id'], after['State']['Pid'], after['State']['StartedAt']) == identity, 'container stopped or restarted during live scan'
    result['same_live_pid_after'] = True
    return result
