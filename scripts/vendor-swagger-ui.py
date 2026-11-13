#!/usr/bin/env python3
"""Vendor only Swagger UI's required assets, with pinned SHA-512 and licenses.

Normal source/Docker builds are offline with respect to these already-vendored
files. Run this explicitly when updating the pinned Swagger UI distribution.
"""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

VERSION = "5.31.0"
URL = f"https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-{VERSION}.tgz"
INTEGRITY = "zSUTIck02fSga6rc0RZP3b7J7wgHXwLea8ZjgLA3Vgnb8QeOl3Wou2/j5QkzSGeoz6HusP/coYuJl33aQxQZpg=="
DEST = Path(__file__).resolve().parents[1] / "server/internal/apidocs/ui"

with urllib.request.urlopen(URL, timeout=30) as response:
    archive = response.read(16 * 1024 * 1024 + 1)
assert len(archive) <= 16 * 1024 * 1024, "distribution archive too large"
assert base64.b64encode(hashlib.sha512(archive).digest()).decode() == INTEGRITY, "SHA-512 mismatch"
DEST.mkdir(parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
    # Read explicit filenames, never extract the archive or trust paths from it.
    for name in ["swagger-ui-bundle.js", "swagger-ui.css", "LICENSE", "NOTICE", "swagger-ui-bundle.js.LICENSE.txt"]:
        entry = tar.extractfile("package/" + name)
        assert entry is not None, f"missing {name}"
        raw = entry.read()
        if name.endswith((".js", ".css")):
            target = DEST / (name + ".gz")
            target.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
        else:
            target = DEST / name
            target.write_bytes(raw)
        print(f"{target.name}: {target.stat().st_size} bytes")
(DEST / "SOURCE.md").write_text(
    f"# 内嵌 Swagger UI\n\n版本：swagger-ui-dist {VERSION}\n\n"
    f"来源：{URL}\n\nSHA-512（Base64）：`{INTEGRITY}`\n\n"
    "由 `python3 scripts/vendor-swagger-ui.py` 生成。仅保留 bundle 和 CSS（确定性 gzip），"
    "不引入 source map、其它构建格式或CDN。运行时仅在打开文档时解压。\n\n"
    "上游许可证与第三方声明见 LICENSE、NOTICE、swagger-ui-bundle.js.LICENSE.txt。\n",
    encoding="utf-8",
)
