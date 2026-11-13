#!/usr/bin/env python3
"""检查双架构主镜像的静态打包工具，并通过 COPY --from 执行真实打包。"""
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
PREFIX = 'authgo-image-pack-' + str(os.getpid())
IMAGE = PREFIX + ':main'
REPORT = BASE / (PREFIX + '.json')
ARCHIVE = BASE / (PREFIX + '.oci.tar')


def disk():
    for path in (ROOT, pathlib.Path('/tmp')):
        assert shutil.disk_usage(path).free >= 10 * 1024**3, '可用磁盘不足 10 GiB'


def run(args, label, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (BASE / (PREFIX + '-' + label + '.log')).write_bytes(result.stdout)
    assert result.returncode == 0, '命令失败，查看对应日志：' + label
    return result.stdout


def static_elf(data, arch):
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', '不是 ELF64 小端可执行文件'
    assert struct.unpack_from('<H', data, 18)[0] == {'amd64': 62, 'arm64': 183}[arch], 'ELF 架构错误'
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    assert size >= 56 and count > 0 and offset + size * count <= len(data), 'ELF 程序头无效'
    assert all(struct.unpack_from('<I', data, offset + size * i)[0] != 3 for i in range(count)), 'ELF 存在动态解释器'
    assert all(struct.unpack_from('<I', data, offset + size * i)[0] != 2 for i in range(count)), 'ELF 存在动态链接段'


def validate(path):
    with tarfile.open(path, 'r:') as archive:
        members = {m.name.removeprefix('./'): m for m in archive if m.isfile()}
        assert 'oci-layout' in members and 'index.json' in members, '缺少 OCI 索引'

        def read(name):
            member = members[name]
            assert member.size <= 128 * 1024**2, 'OCI blob 超过 128 MiB'
            return archive.extractfile(member).read()

        def blob(desc):
            assert re.fullmatch(r'sha256:[0-9a-f]{64}', desc['digest']), '不支持的摘要'
            data = read('blobs/sha256/' + desc['digest'][7:])
            assert len(data) == desc['size'] and hashlib.sha256(data).hexdigest() == desc['digest'][7:], 'OCI 摘要不匹配'
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
            assert cfg['os'] == 'linux' and arch in ('amd64', 'arm64') and arch not in found, '镜像平台错误'
            assert cfg['config']['User'] == '65532:65532' and cfg['config']['Entrypoint'] == ['/authgo'], '主镜像运行身份或入口改变'
            env = dict(value.split('=', 1) for value in cfg['config']['Env'])
            assert env['AUTHGO_ADDR'] == ':8080' and env['AUTHGO_DATA_DIR'] == '/data'
            assert cfg['config']['WorkingDir'] == '/data' and '/data' in cfg['config']['Volumes']
            assert cfg['config']['Healthcheck']['Test'] == ['CMD', '/authgo', 'healthcheck']
            files, diffids = {}, []
            for layer in obj['layers']:
                packed = blob(layer)
                media = layer['mediaType']
                if media in ('application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'):
                    raw = gzip.decompress(packed)
                else:
                    assert media in ('application/vnd.oci.image.layer.v1.tar', 'application/vnd.docker.image.rootfs.diff.tar'), '不支持的层压缩格式'
                    raw = packed
                diffids.append('sha256:' + hashlib.sha256(raw).hexdigest())
                with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as layer_tar:
                    for member in layer_tar:
                        name = member.name.removeprefix('./').lstrip('/')
                        if name in ('.wh.authgo', '.wh.authgo-pack'):
                            files.pop(name.removeprefix('.wh.'), None)
                        if name in ('authgo', 'authgo-pack'):
                            assert member.isfile() and member.mode & 0o111, '镜像可执行文件类型或权限错误'
                            files[name] = layer_tar.extractfile(member).read()
            assert cfg['rootfs']['type'] == 'layers' and cfg['rootfs']['diff_ids'] == diffids, '镜像层 diffID 不匹配'
            assert set(files) == {'authgo', 'authgo-pack'}, '主镜像缺少服务端或打包工具'
            for data in files.values():
                static_elf(data, arch)
            pack = files['authgo-pack']
            assert b'authgo-stub-linux-amd64' in pack and b'authgo-stub-linux-arm64' in pack, '打包工具缺少双架构启动桩'
            found[arch] = {'manifest_digest': desc['digest'], 'pack_bytes': len(pack), 'pack_sha256': hashlib.sha256(pack).hexdigest(), 'static_elf': True}

        for desc in json.loads(read('index.json'))['manifests']:
            visit(desc)
        assert set(found) == {'amd64', 'arm64'}, '缺少目标架构'
        return {'platforms': found, 'attestations': attestations, 'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main(keep):
    disk()
    consumer, extract = PREFIX + '-consumer:local', PREFIX + '-extract'
    success = False
    try:
        # OCI export keeps both architectures; avoid zstd so stdlib validation can read every layer.
        run(['docker', 'buildx', 'build', '--file', 'Dockerfile', '--platform', 'linux/amd64,linux/arm64',
             '--tag', IMAGE, '--output', 'type=oci,dest=' + str(ARCHIVE) + ',compression=gzip,force-compression=true', '.'], 'build')
        result = validate(ARCHIVE)
        print('PASS 双架构主镜像包含静态 authgo 与 authgo-pack', flush=True)
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
                print('PASS 篡改 OCI blob 被拒绝', flush=True)
            else:
                raise AssertionError('篡改 OCI blob 未被拒绝')
            disk()
            run(['docker', 'load', '-i', str(ARCHIVE)], 'load')
            for arch in ('amd64', 'arm64'):
                info = json.loads(run(['docker', 'image', 'inspect', '--platform=linux/' + arch, IMAGE], 'inspect-' + arch))[0]
                assert info['Architecture'] == arch and info['Config']['Entrypoint'] == ['/authgo']
            native = run(['docker', 'info', '--format', '{{.Architecture}}'], 'host-arch').decode().strip()
            arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'amd64': 'amd64', 'arm64': 'arm64'}.get(native)
            assert arch, '本机架构不受支持'
            vector = json.loads((ROOT / 'sdk/vectors/payload-envelope.json').read_text())
            config = vector['payload']['config']
            public = base64.urlsafe_b64encode(bytes.fromhex(vector['recipient_public_hex'])).decode().rstrip('=')
            marker = b'AUTHGO_MAIN_IMAGE_COPY_CORE'
            (tmp / 'business.js').write_bytes(b'module.exports = ' + json.dumps(marker.decode()).encode() + b';\n')
            shutil.copytree(ROOT / 'sdk/go', tmp / 'sdk', ignore=shutil.ignore_patterns('*_test.go', 'internal', '*.test', '*.out'))
            (tmp / 'go.mod').write_text('module image-pack-core\n\ngo 1.26.0\nrequire authgo/sdk v1.0.0\nreplace authgo/sdk => ./sdk\n')
            (tmp / 'main.go').write_text('package main\nimport (\n"context"\nsdk "authgo/sdk"\n)\nconst config = ' + json.dumps(config) + '\nfunc main() {\n g,e := sdk.StartGuard(context.Background(),sdk.GuardOptions{Config:config,Version:"1.2.3"}); if e!=nil { panic(e) }; defer g.Close(context.Background()); if e=g.Require(""); e!=nil { panic(e) }\n}\n')
            (tmp / 'build.sh').write_text('''#!/bin/sh
set -eu
/authgo-pack --node core=/core/business.js --public-key "$PACK_PUBLIC" --key-id image-pack --app-key app_test --version 1.2.3 --config "$PACK_CONFIG" --out /payload
/authgo-pack --verify --out /payload
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOMAXPROCS=2 go build -p 1 -o /core-$arch .
  /authgo-pack --protect /core-$arch --public-key "$PACK_PUBLIC" --key-id image-pack --app-key app_test --version 1.2.3 --config "$PACK_CONFIG" --out /protected-$arch
  /authgo-pack --verify --out /protected-$arch
done
''')
            (tmp / 'Dockerfile').write_text('FROM golang:1.26-alpine AS packaging\nCOPY --from=' + IMAGE + ' /authgo-pack /authgo-pack\nCOPY business.js main.go go.mod /core/\nCOPY sdk/ /core/sdk/\nWORKDIR /core\nCOPY build.sh /build.sh\nARG PACK_CONFIG\nARG PACK_PUBLIC\nRUN sh /build.sh\nFROM scratch\nCOPY --from=' + IMAGE + ' /authgo-pack /authgo-pack\nCOPY --from=packaging --chown=65532:65532 /payload /payload\nCOPY --from=packaging /core-amd64 /protected-amd64\nCOPY --from=packaging /core-arm64 /protected-arm64\nUSER 65532:65532\nENTRYPOINT ["/authgo-pack"]\n')
            output = run(['docker', 'build', '--memory=1536m', '--platform=linux/' + arch, '--build-arg', 'PACK_CONFIG=' + config,
                          '--build-arg', 'PACK_PUBLIC=' + public, '-t', consumer, '.'], 'consumer', tmp)
            assert config.encode() not in output and marker not in output, '构建输出泄露配置或明文标记'
            output = run(['docker', 'run', '--rm', '--name', PREFIX + '-verify', '--memory=64m', '--network=none', '--read-only',
                          '--cap-drop=ALL', '--security-opt=no-new-privileges:true', consumer, '--verify', '--out', '/payload'], 'verify')
            assert output.strip() == b'structure verified (not authenticated)'
            run(['docker', 'create', '--name', extract, consumer], 'create')
            for target in ('amd64', 'arm64'):
                file = tmp / ('protected-' + target)
                run(['docker', 'cp', extract + ':/protected-' + target, str(file)], 'copy-' + target)
                data = file.read_bytes()
                footer = data[-64:]
                assert footer[:16] == b'AUTHGO-STUB-v1\0\0'
                length = struct.unpack_from('>Q', footer, 24)[0]
                assert length > 100000 and length < len(data) - 64, '启动桩长度无效'
                static_elf(data[:length], target)
            result.update(native_image=IMAGE, native_execution=arch, copy_from_pack_verify=True, real_embedded_launchers=['amd64', 'arm64'])
            result['authorization_e2e'] = '独立的受保护镜像矩阵负责授权与生命周期验证；本脚本校验打包和产物结构。'
        REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        success = True
        print('IMAGE_PACK_DONE 0 image=' + IMAGE, flush=True)
    finally:
        for name in (extract, PREFIX + '-verify'):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in (consumer, *([] if keep and success else [IMAGE])):
            subprocess.run(['docker', 'image', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('IMAGE_PACK_OWNED_CLEANUP keep_image=' + str(bool(keep and success)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep-image', action='store_true', help='保留通过检查的主镜像标签')
    main(parser.parse_args().keep_image)
