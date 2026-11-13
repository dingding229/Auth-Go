"""Private bounded v2 index and in-memory slot validation (not public metadata)."""

import json
import re

from .payload import _integer, _invalid

_LIMIT = 65535
_MAX = (2**63 - 1) // 2
_SLOT = 96


def _decimal(value, limit=_MAX):
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        raise _invalid()
    number = int(value)
    if number > limit:
        raise _invalid()
    return number


def _safe_entry(value):
    if (
        type(value) is not str or not value
        or any(c in value for c in ("\\", "\0", ":"))
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or any(p in ("", ".", "..") for p in value.split("/"))
    ):
        raise _invalid()
    value.encode("utf8", errors="strict")


def _read_index(raw):
    """Parse only this exact schema, bounding arrays BEFORE appending values."""
    if not isinstance(raw, (bytes, bytearray)) or not 1 <= len(raw) <= 8 << 20:
        raise _invalid()
    source = raw.decode("utf8", errors="strict")
    decoder = json.JSONDecoder()
    at = 0
    counts = {"files": 0, "entries": 0, "offsets": 0}

    def ws():
        nonlocal at
        while at < len(source) and source[at] in " \r\n\t":
            at += 1

    def take(char):
        nonlocal at
        ws()
        if at >= len(source) or source[at] != char:
            raise _invalid()
        at += 1

    def text():
        nonlocal at
        ws()
        if at >= len(source) or source[at] != '"':
            raise _invalid()
        value, at = decoder.raw_decode(source, at)
        value.encode("utf8", errors="strict")
        return value

    def array(name, read):
        take("[")
        out = []
        ws()
        if at < len(source) and source[at] == "]":
            take("]")
            return out
        while True:
            if name == "path":
                if len(out) >= 8:
                    raise _invalid()
            else:
                if counts[name] >= _LIMIT:
                    raise _invalid()
                counts[name] += 1
            out.append(read())
            ws()
            if at < len(source) and source[at] == "]":
                take("]")
                return out
            take(",")

    def obj(schema):
        take("{")
        out = {}
        while True:
            key = text()
            if key not in schema or key in out:
                raise _invalid()
            take(":")
            out[key] = schema[key]()
            ws()
            if at < len(source) and source[at] == "}":
                take("}")
                if out.keys() != schema.keys():
                    raise _invalid()
                return out
            take(",")

    def entry():
        return obj({"path": lambda: array("path", text), "offsets": lambda: array("offsets", text)})

    def file():
        return obj({"index": text, "entries": lambda: array("entries", entry)})

    out = obj({"v": text, "tag": text, "files": lambda: array("files", file)})
    ws()
    if at != len(source):
        raise _invalid()
    return out


def parse_watermark_index(raw, files):
    try:
        out = _read_index(raw)
        if out["v"] != "1" or not re.fullmatch(r"[0-9a-f]{32}", out["tag"]):
            raise _invalid()
        if not 1 <= len(files) <= _LIMIT or not out["files"]:
            raise _invalid()
        seen = set()
        for file in out["files"]:
            index = _decimal(file["index"], _LIMIT - 1)
            if index >= len(files) or index in seen or files[index]["kind"] == "watermark" or not file["entries"]:
                raise _invalid()
            seen.add(index)
            public = files[index]
            paths = set()
            count = 0
            for entry in file["entries"]:
                path, offsets = entry["path"], entry["offsets"]
                for name in path:
                    _safe_entry(name)
                kind = public["kind"]
                if (
                    kind in ("node", "protect") and path
                    or kind in ("python", "php", "dotnet") and len(path) != 1
                    or kind == "java" and not path
                    or kind not in ("node", "protect", "python", "php", "dotnet", "java")
                    or kind == "dotnet" and ("/" in path[0] or not path[0].lower().endswith(".dll"))
                ):
                    raise _invalid()
                identity = tuple(name.lower() for name in path)
                if identity in paths or not offsets:
                    raise _invalid()
                paths.add(identity)
                last = -_SLOT
                for value in offsets:
                    n = _decimal(value)
                    if n < last + _SLOT or not path and n + _SLOT > _integer(public["size"]):
                        raise _invalid()
                    last = n
                count += len(offsets)
            if count < 8:
                raise _invalid()
        if seen != {i for i, f in enumerate(files) if f["kind"] != "watermark"}:
            raise _invalid()
        return out
    except Exception:
        raise _invalid() from None


def apply_watermark(targets, index, file_index, watermark):
    """Validate ALL referenced archive members/slots before the first mutation.

    targets maps exact tuple paths to writable bytearrays. No marker discovery:
    offsets refer to genuine code constants already inserted by the packer.
    """
    try:
        if len(watermark) != 32 or not any(watermark) or not re.fullmatch(r"[0-9a-f]{32}", index["tag"]):
            raise _invalid()
        selected = next(f for f in index["files"] if _decimal(f["index"], _LIMIT - 1) == file_index)
        expected = index["tag"].encode("ascii") + b"0" * 64
        pending = []
        for entry in selected["entries"]:
            target = targets[tuple(entry["path"])]
            if not isinstance(target, bytearray):
                raise _invalid()
            last = -_SLOT
            for value in entry["offsets"]:
                n = _decimal(value)
                if n < last + _SLOT or n + _SLOT > len(target) or target[n:n + _SLOT] != expected:
                    raise _invalid()
                pending.append((target, n + 32))
                last = n
        if len(pending) < 8:
            raise _invalid()
        encoded = bytearray(watermark.hex().encode("ascii"))
        try:
            for target, n in pending:
                target[n:n + 64] = encoded
        finally:
            encoded[:] = b"\0" * len(encoded)
    except Exception:
        raise _invalid() from None
