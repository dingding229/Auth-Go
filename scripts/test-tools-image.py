#!/usr/bin/env python3
"""Payload test for make tools-image's DEFAULT OCI exporter, not type=local.
No push, no added dependency. Validate descriptors/config/layers/ELF, docker load,
and real COPY --from + native encryption/verify. ARM ELF is inspected, not run.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = ROOT.parent
PREFIX = 'authgo-payload-tools-default-' + str(os.getpid())
IMAGE = PREFIX + ':default'
REPORT = BASE / 'tools-image-default.json'
ARCHIVE = BASE / 'tools-image-default.oci.tar'


def disk():
    for path in (ROOT, pathlib.Path('/tmp')):
        free = shutil.disk_usage(path).free
        assert free >= 10 * 1024**3, 'disk below 10GiB; no pruning'
        print('DISK_FREE_KIB ' + str(path) + ' ' + str(free // 1024), flush=True)


def run(args, label, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (BASE / ('tools-image-' + label + '.log')).write_bytes(result.stdout)
    assert result.returncode == 0, 'tools command failed: ' + label
    return result.stdout


def validate(path):
    with tarfile.open(path, 'r:') as archive:
        members = {m.name.removeprefix('./'): m for m in archive if m.isfile()}
        assert 'oci-layout' in members and 'index.json' in members, 'not an OCI image archive'

        def read(name):
            member = members[name]
            assert member.size <= 128 * 1024**2, 'oversized OCI blob'
            return archive.extractfile(member).read()

        def blob(desc):
            assert re.fullmatch(r'sha256:[0-9a-f]{64}', desc['digest']), 'unsupported digest'
            data = read('blobs/sha256/' + desc['digest'][7:])
            assert len(data) == desc['size'] and hashlib.sha256(data).hexdigest() == desc['digest'][7:], 'blob integrity mismatch'
            return data

        assert json.loads(read('oci-layout'))['imageLayoutVersion'] == '1.0.0'
        found, attestations = {}, 0

        def visit(desc):
            nonlocal attestations
            obj = json.loads(blob(desc))
            if 'manifests' in obj:
                for child in obj['manifests']:
                    visit(child)
                return
            cfg = json.loads(blob(obj['config']))
            if desc.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
                for layer in obj['layers']:
                    assert layer['mediaType'] == 'application/vnd.in-toto+json'
                    json.loads(blob(layer))
                attestations += 1
                return
            arch = cfg['architecture']
            assert cfg['os'] == 'linux' and arch in ('amd64', 'arm64') and arch not in found
            assert cfg['config']['User'] == '65532:65532' and cfg['config']['Entrypoint'] == ['/authgo-pack']
            assert len(obj['layers']) == 1 and cfg['rootfs']['type'] == 'layers'
            layer = obj['layers'][0]
            packed = blob(layer)
            if layer['mediaType'] in ('application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'):
                raw = gzip.decompress(packed)
            else:
                assert layer['mediaType'] in ('application/vnd.oci.image.layer.v1.tar', 'application/vnd.docker.image.rootfs.diff.tar'), 'unsupported layer compression'
                raw = packed
            assert cfg['rootfs']['diff_ids'] == ['sha256:' + hashlib.sha256(raw).hexdigest()]
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as layer_tar:
                files = [m for m in layer_tar if not m.isdir()]
                assert len(files) == 1 and files[0].name.removeprefix('./').lstrip('/') == 'authgo-pack' and files[0].isfile(), 'tool image contains files other than authgo-pack'
                executable = layer_tar.extractfile(files[0]).read()
                assert files[0].mode & 0o111 and executable[:6] == b'\x7fELF\x02\x01'
                machine = struct.unpack_from('<H', executable, 18)[0]
                assert machine == {'amd64': 62, 'arm64': 183}[arch], 'ELF machine does not match image platform'
                # Production pack must embed both launcher architectures.
                assert b'authgo-stub-linux-amd64' in executable and b'authgo-stub-linux-arm64' in executable
            found[arch] = {'manifest_digest': desc['digest'], 'layer_media_type': layer['mediaType'], 'elf_machine': machine, 'elf_bytes': len(executable), 'binary_sha256': hashlib.sha256(executable).hexdigest(), 'only_file': '/authgo-pack'}

        for desc in json.loads(read('index.json'))['manifests']:
            visit(desc)
        assert set(found) == {'amd64', 'arm64'}, 'missing architecture'
        return {'platforms': found, 'attestations': attestations, 'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main(keep):
    disk()
    assert ROOT.is_dir(), 'repository root is missing'
    assert not subprocess.run(['docker', 'image', 'inspect', IMAGE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0, 'owned tag already exists'
    result = {'make_overrides': {'TOOLS_IMAGE': PREFIX, 'TOOLS_VERSION': 'default'}, 'output_override': False, 'platforms_override': False}
    consumer = PREFIX + '-consumer:local'
    success = False
    try:
        # Host lacks make; this bounded make frontend uses the same host paths and
        # Docker daemon. Do not change/create a builder or its shared config.
        run(['docker', 'run', '--rm', '--name', PREFIX + '-make', '--memory=1536m', '--cpus=2',
             '-v', str(BASE) + ':' + str(BASE), '-v', '/usr/bin/docker:/usr/bin/docker:ro',
             '-v', '/usr/libexec/docker/cli-plugins:/usr/libexec/docker/cli-plugins:ro',
             '-v', '/var/run/docker.sock:/var/run/docker.sock', '-w', str(ROOT), 'rust:1.96.1',
             'make', 'tools-image', 'TOOLS_IMAGE=' + PREFIX, 'TOOLS_VERSION=default'], 'make-default')
        default = ROOT / 'bin/authgo-tools-default.oci.tar'
        assert default.is_file(), 'default OCI output missing'
        shutil.copy2(default, ARCHIVE)
        result.update(validate(ARCHIVE))
        print('PASS DEFAULT_OCI_BOTH_ARCHITECTURES ' + json.dumps(result['platforms']), flush=True)
        # Integrity negative control: a modified referenced blob must fail.
        with tempfile.TemporaryDirectory(prefix=PREFIX, dir=BASE) as tmp:
            tmp = pathlib.Path(tmp)
            corrupted = tmp / 'corrupt.tar'
            with tarfile.open(ARCHIVE, 'r:') as source, tarfile.open(corrupted, 'w') as dest:
                for member in source:
                    data = source.extractfile(member).read() if member.isfile() else None
                    if data and member.name.removeprefix('./').startswith('blobs/sha256/'):
                        data = bytes([data[0] ^ 1]) + data[1:]
                    dest.addfile(member, io.BytesIO(data) if data is not None else None)
            try:
                validate(corrupted)
            except (AssertionError, ValueError, KeyError):
                print('PASS DEFAULT_OCI_TAMPER_REJECTED', flush=True)
            else:
                raise AssertionError('modified OCI blob was accepted')
            disk()
            run(['docker', 'load', '-i', str(ARCHIVE)], 'load-default')
            for arch in ('amd64', 'arm64'):
                info = json.loads(run(['docker', 'image', 'inspect', '--platform=linux/' + arch, IMAGE], 'inspect-default-' + arch))[0]
                assert info['Architecture'] == arch and info['Config']['Entrypoint'] == ['/authgo-pack']
            # Real consumer takes the tool from the imported DEFAULT OCI image.
            vector = json.loads((ROOT / 'sdk/vectors/payload-envelope.json').read_text())
            config = vector['payload']['config']  # explicitly public synthetic trust fixture
            public = base64.urlsafe_b64encode(bytes.fromhex(vector['recipient_public_hex'])).decode().rstrip('=')
            marker = b'AUTHGO_payload_DEFAULT_OCI_COPY_CORE'
            (tmp / 'business.js').write_bytes(b'module.exports = ' + json.dumps(marker.decode()).encode() + b';\n')
            (tmp / 'build.sh').write_text('#!/bin/sh\nset -eu\n/authgo-pack --node core=/core/business.js --public-key "$PACK_PUBLIC" --key-id default-oci --app-key app_test --version 1.2.3 --config "$PACK_CONFIG" --out /payload\n/authgo-pack --verify --out /payload\n')
            (tmp / 'Dockerfile').write_text('FROM alpine:3.22 AS packaging\nCOPY --from=' + IMAGE + ' /authgo-pack /authgo-pack\nCOPY business.js /core/business.js\nCOPY build.sh /build.sh\nARG PACK_CONFIG\nARG PACK_PUBLIC\nRUN sh /build.sh\nFROM scratch\nCOPY --from=' + IMAGE + ' /authgo-pack /authgo-pack\nCOPY --from=packaging --chown=65532:65532 /payload /payload\nUSER 65532:65532\nENTRYPOINT ["/authgo-pack"]\n')
            output = run(['docker', 'build', '--memory=768m', '--platform=linux/amd64', '--build-arg', 'PACK_CONFIG=' + config, '--build-arg', 'PACK_PUBLIC=' + public, '-t', consumer, '.'], 'copy-from-consumer', tmp)
            assert config.encode() not in output and marker not in output, 'build output contains config or plaintext marker'
            output = run(['docker', 'run', '--rm', '--name', PREFIX + '-verify', '--platform=linux/amd64', '--memory=64m', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', consumer, '--verify', '--out', '/payload'], 'native-verify')
            assert output.strip() == b'structure verified (not authenticated)'
            result['native_image'] = IMAGE
            result['copy_from_and_native_pack_verify'] = 'PASS (structure only, not authorization E2E)'
            result['arm64_execution'] = 'NOT RUN: ELF/platform inspected, native runtime not claimed'
            print('PASS DEFAULT_OCI_LOAD_COPY_NATIVE_PACK_VERIFY', flush=True)
        REPORT.write_text(json.dumps(result, indent=2) + '\n')
        success = True
        print('TOOLS_DEFAULT_IMAGE_DONE 0', flush=True)
    finally:
        for name in (PREFIX + '-make', PREFIX + '-verify'):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in (consumer, *([] if keep and success else [IMAGE])):
            subprocess.run(['docker', 'image', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('TOOLS_DEFAULT_OWNED_CLEANUP keep_native=' + str(bool(keep and success)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--keep-image', action='store_true', help='retain own imported tag for sequential protected matrices')
    main(parser.parse_args().keep_image)
