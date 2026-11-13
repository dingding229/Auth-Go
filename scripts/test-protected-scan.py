#!/usr/bin/env python3
"""Scanner regressions and real Docker clean/deliberate-leak controls."""
import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import protected_scan as s


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def jar(data):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('Main.class', data)
    return out.getvalue()


def saved(layer, oci=False, codec=None):
    raw = codec(layer) if codec else layer
    if not oci:
        return tar({'manifest.json': json.dumps([{'Layers': ['layer.tar']}]).encode(), 'layer.tar': raw})
    digest = lambda data: 'sha256:' + hashlib.sha256(data).hexdigest()
    layer_type = 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if codec else '')
    manifest = json.dumps({'layers': [{'digest': digest(raw), 'mediaType': layer_type}]}).encode()
    return tar({'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': json.dumps({'manifests': [{'digest': digest(manifest)}]}).encode(), 'blobs/sha256/' + digest(manifest)[7:]: manifest, 'blobs/sha256/' + digest(raw)[7:]: raw})


class ScanTests(unittest.TestCase):
    def scan(self, raw, name='docker.tar'):
        scanner = s.Scanner()
        scanner.content(io.BytesIO(raw), name)
        return scanner

    def test_clean_and_leaked_archive_matrix(self):
        # 2 layouts x 4 codecs x clean/3 marker encodings = 32 paired checks.
        for oci in (False, True):
            for codec in (None, gzip.compress, bz2.compress, lzma.compress):
                for marker in (b'clean business', *s.MARKERS):
                    with self.subTest(oci=oci, codec=str(codec), leaked=marker in s.MARKERS):
                        raw = saved(tar({'app/business.jar': jar(marker)}), oci, codec)
                        if marker in s.MARKERS:
                            with self.assertRaises(s.Leak):
                                self.scan(raw)
                        else:
                            self.assertEqual(self.scan(raw).saved_image()['verified_layers'], 1)

    def test_malformed_nested_archive_fails_closed(self):
        with self.assertRaisesRegex(AssertionError, 'invalid tar'):
            self.scan(tar({'upstream-regression-fixture.tar': b'invalid tar'}))
        with self.assertRaises(s.Leak):
            self.scan(tar({'upstream-regression-fixture.tar': b'invalid tar' + s.MARKER}))
        with self.assertRaisesRegex(AssertionError, 'invalid tar'):
            self.scan(saved(b'invalid tar')).saved_image()
        with self.assertRaises(zipfile.BadZipFile):
            self.scan(tar({'invalid.zip': b'PK\x03\x04broken'}))

    def test_zero_filled_plain_file_is_not_tar(self):
        self.assertEqual(self.scan(bytes(512), 'var/log/lastlog').formats, {})

    def test_archive_trailing_data_is_not_ignored(self):
        for codec in (lambda x: x, gzip.compress):
            self.scan(codec(tar({'clean': b'clean'}) + b'clean trailer'))
            with self.assertRaises(s.Leak):
                self.scan(codec(tar({'clean': b'clean'}) + s.MARKER))

    def test_chunk_boundary_all_encodings(self):
        for marker in s.MARKERS:
            with self.subTest(encoding=len(marker)):
                with self.assertRaises(s.Leak):
                    self.scan(b'x' * (1024 * 1024 - len(marker) // 2) + marker, 'raw')

    def test_unsupported_compression_fails_closed(self):
        for magic in (b'\x28\xb5\x2f\xfd', b'\x04\x22\x4d\x18', b'\x50\x2a\x4d\x18'):
            with self.assertRaisesRegex(AssertionError, 'unsupported'):
                self.scan(magic, 'blob')

    def test_missing_layer_or_unknown_layout_fails(self):
        for raw in (tar({'hello': b'clean'}), tar({'manifest.json': b'[{"Layers":["absent.tar"]}]'})):
            with self.assertRaises(AssertionError):
                self.scan(raw).saved_image()

    def test_corrupt_compressed_layer_fails(self):
        with self.assertRaises((EOFError, OSError)):
            self.scan(saved(gzip.compress(tar({'app': b'clean'}))[:-8]))

    def test_limits_fail_closed(self):
        scanner = s.Scanner()
        scanner.bytes = s.MAX_BYTES
        with self.assertRaisesRegex(AssertionError, 'limit'):
            scanner.content(io.BytesIO(b'clean'), 'raw')
        scanner = s.Scanner()
        scanner.files = s.MAX_FILES
        with self.assertRaisesRegex(AssertionError, 'limit'):
            scanner.content(io.BytesIO(b''), 'raw')
        with self.assertRaisesRegex(AssertionError, 'nesting'):
            s.Scanner().content(io.BytesIO(b''), 'raw', depth=9)

    def test_rejected_archive_cleanup_kills_stuck_export(self):
        class StuckExport:
            def __init__(self):
                self.stdout = io.BytesIO(b'invalid tar')
                self.terminated = self.killed = False

            def poll(self):
                return None

            def terminate(self):
                assert self.stdout.closed, 'pipe must close before terminate'
                self.terminated = True

            def wait(self, timeout):
                if not self.killed:
                    raise subprocess.TimeoutExpired('test-only', timeout)
                return -9

            def kill(self):
                self.killed = True

        process = StuckExport()
        with patch.object(s.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(AssertionError, 'invalid tar'):
                s.docker_scan(['export', 'authgo-synthetic-unit-only'])
        self.assertTrue(process.terminated and process.killed)

    def test_filesystem_no_symlinks_or_fifos(self):
        with tempfile.TemporaryDirectory(prefix='authgo-scan-unit-') as tmp:
            root = pathlib.Path(tmp)
            (root / 'clean').write_bytes(b'clean')
            (root / 'self').symlink_to('.')
            os.mkfifo(root / 'fifo')
            self.assertGreaterEqual(s.scan_tree(root)['entries'], 1)
            (root / 'leak').write_bytes(s.MARKER)
            with self.assertRaises(s.Leak):
                s.scan_tree(root)


def controls():
    base = pathlib.Path(os.environ.get('AUTHGO_TEST_WORKDIR', pathlib.Path(__file__).resolve().parent.parent))
    assert shutil.disk_usage(base).free >= 10 * 1024**3, 'disk below 10GiB; no pruning'
    prefix = 'authgo-contract-payload-scan-' + str(os.getpid())
    clean, dirty, name, volume = (prefix + x for x in ('-clean', '-dirty', '-live', '-cache'))
    made_images, made_containers, made_volumes = [], [], []

    def docker(*args):
        result = subprocess.run(['docker', *args], capture_output=True, text=True)
        assert result.returncode == 0, 'control docker command failed: ' + result.stderr[-600:]
        return result.stdout

    def inspect(container):
        return json.loads(docker('inspect', container))[0]

    def leak_expected(fn, label):
        try:
            fn()
        except s.Leak:
            print('PASS DELIBERATE_LEAK_REJECTED ' + label, flush=True)
        else:
            raise AssertionError('scanner accepted deliberate leak: ' + label)

    try:
        with tempfile.TemporaryDirectory(prefix=prefix, dir=base) as tmp:
            context = pathlib.Path(tmp)
            (context / 'Dockerfile').write_text('FROM alpine:3.22\nRUN mkdir -p /control /var/lib/authgo && chown 65532:65532 /control /var/lib/authgo\nUSER 65532:65532\nCMD ["sleep","300"]\n')
            made_images.append(clean)
            docker('build', '--memory=128m', '-t', clean, tmp)
            evidence = s.docker_scan(['save', clean])
            print('PASS CLEAN_ACTUAL_DOCKER_SAVE ' + json.dumps(evidence), flush=True)
            (context / 'marker').write_bytes(s.MARKER)
            # Marker deleted in a later layer: merged export is clean, ALL-layer save is not.
            (context / 'Dockerfile').write_text('FROM ' + clean + '\nCOPY marker /control/marker\nUSER 0\nRUN rm /control/marker\nUSER 65532:65532\n')
            made_images.append(dirty)
            docker('build', '--memory=128m', '-t', dirty, tmp)
            leak_expected(lambda: s.docker_scan(['save', dirty]), 'actual docker save deleted earlier layer')
            made_volumes.append(volume)
            docker('volume', 'create', volume)
            made_containers.append(name)
            docker('run', '-d', '--name', name, '--network=none', '--memory=64m', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--tmpfs', '/tmp:rw,nosuid,size=8m', '-v', volume + ':/var/lib/authgo', dirty)
            pid = inspect(name)['State']['Pid']
            print('PASS CLEAN_LIVE ' + json.dumps(s.live_scan(name, volume, inspect)), flush=True)
            for path in ('/var/lib/authgo/marker', '/control/marker', '/tmp/marker', '/dev/shm/marker'):
                docker('exec', name, 'sh', '-c', 'printf %s ' + s.MARKER.decode() + ' > ' + path)
                if not path.startswith('/control/'):
                    s.docker_scan(['export', name])
                    print('PASS EXPORT_OMITS_MOUNT_LEAK ' + path, flush=True)
                leak_expected(lambda: s.live_scan(name, volume, inspect), 'live ' + path)
                docker('exec', name, 'rm', path)
                result = s.live_scan(name, volume, inspect)
                assert result['pid'] == pid and result['same_live_pid_after']
                print('PASS CLEAN_SAME_LIVE_PID_AFTER_REMOVAL ' + path, flush=True)
            print('SCANNER_DOCKER_CONTROLS_DONE 0', flush=True)
    finally:
        for container in made_containers:
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
        for vol in made_volumes:
            subprocess.run(['docker', 'volume', 'rm', vol], capture_output=True)
        for image in reversed(made_images):
            subprocess.run(['docker', 'image', 'rm', image], capture_output=True)
        print('SCANNER_OWNED_RESOURCES_CLEANED', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--docker-controls', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ScanTests))
    assert result.wasSuccessful(), 'scanner unit regression failed'
    if args.docker_controls:
        controls()
