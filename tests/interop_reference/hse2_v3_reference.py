"""Small independent HSE2 v3 keyfile writer/reader used for interop checks.

This module intentionally does not import high_security_encryptor. It supports
only the keyfile wrapper and the documented AES-256-GCM v3 profile.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from Crypto.Cipher import AES


PREAMBLE = struct.Struct(">4sBBHQ")
MANIFEST_PREFIX = struct.Struct(">4sQ")
CHUNK_PREFIX = struct.Struct(">4sQI")
CHUNK_SIZE = 64 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _kek(keyfile: bytes) -> bytes:
    if len(keyfile) < 32:
        raise ValueError("keyfile must contain at least 32 bytes")
    return hashlib.sha256(b"HSE2:keyfile-kek:v1:" + keyfile).digest()


def _wrapper_dek_mek(wrapper: dict, keyfile: bytes) -> tuple[bytes, bytes]:
    kek = _kek(keyfile)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=_unb64(wrapper["nonce"]))
    cipher.update(b"HSE2:wrapper-record:keyfile")
    plain = cipher.decrypt_and_verify(
        _unb64(wrapper["wrapped_keys"]["dek"]) + _unb64(wrapper["wrapped_keys"]["mek"]),
        _unb64(wrapper["auth_tag"]),
    )
    if len(plain) != 64:
        raise ValueError("wrapped content keys must total 64 bytes")
    return plain[:32], plain[32:]


def _header_keys(header: dict, keyfile: bytes) -> tuple[bytes, bytes]:
    if header.get("format") != "HSE2" or header.get("format_version") != 3:
        raise ValueError("expected HSE2 v3 header")
    wrappers = header.get("wrappers")
    if not isinstance(wrappers, list) or len(wrappers) != 1 or wrappers[0].get("type") != "keyfile":
        raise ValueError("reference profile requires exactly one keyfile wrapper")
    dek, mek = _wrapper_dek_mek(wrappers[0], keyfile)
    unsigned = json.loads(json.dumps(header))
    tag = _unb64(unsigned["header_auth"].pop("tag"))
    expected = hmac.new(mek, b"HSE2:header-auth:v1" + _canonical(unsigned), hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("header authentication failed")
    return dek, mek


def write_archive(path: str | os.PathLike[str], files: dict[str, bytes], keyfile: bytes) -> None:
    """Write a v3 archive from relative POSIX paths and bytes."""
    if not files:
        raise ValueError("at least one file is required")
    if any(not name or "\\" in name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in files):
        raise ValueError("unsafe archive path")
    dek, mek = os.urandom(32), os.urandom(32)
    nonce = os.urandom(12)
    wrapped = AES.new(_kek(keyfile), AES.MODE_GCM, nonce=nonce)
    wrapped.update(b"HSE2:wrapper-record:keyfile")
    wrapped_ct, wrapped_tag = wrapped.encrypt_and_digest(dek + mek)
    wrapper = {
        "id": "reference-keyfile-1", "type": "keyfile", "created_utc": "2026-01-01T00:00:00Z",
        "label": "independent reference", "kdf": {
            "algorithm": "sha256-domain-separated", "keyfile_size": len(keyfile),
            "keyfile_sha256": hashlib.sha256(keyfile).hexdigest(),
        }, "wrap_cipher": "AES-256-GCM", "nonce": _b64(nonce),
        "wrapped_keys": {"dek": _b64(wrapped_ct[:32]), "mek": _b64(wrapped_ct[32:])},
        "auth_tag": _b64(wrapped_tag),
    }
    ordered = sorted(files.items())
    entries, ranges, chunks, next_index = [], [], [], 0
    for name, content in ordered:
        entries.append({"path": name, "kind": "file", "size": len(content)})
        count = (len(content) + CHUNK_SIZE - 1) // CHUNK_SIZE
        ranges.append({"path": name, "size": len(content), "start_chunk": next_index, "chunk_count": count})
        for start in range(0, len(content), CHUNK_SIZE):
            part = content[start:start + CHUNK_SIZE]
            n = os.urandom(12)
            cipher = AES.new(dek, AES.MODE_GCM, nonce=n)
            cipher.update(f"HSE2:payload-chunk:v1:{next_index}".encode("ascii"))
            ct, tag = cipher.encrypt_and_digest(part)
            chunks.append((next_index, n, ct, tag))
            next_index += 1
    manifest = {"format": "HSE2-archive-manifest-v1", "entries": entries,
                "payload_ranges": ranges, "chunk_size": CHUNK_SIZE}
    mn = os.urandom(12)
    mc = AES.new(mek, AES.MODE_GCM, nonce=mn)
    mc.update(b"HSE2:manifest:v1")
    manifest_ct, manifest_tag = mc.encrypt_and_digest(_canonical(manifest))
    header = {
        "format": "HSE2", "format_version": 3, "created_utc": "2026-01-01T00:00:00Z",
        "cipher_suite": {"payload_cipher": "AES-256-GCM", "manifest_cipher": "AES-256-GCM",
                         "wrap_cipher": "AES-256-GCM", "chunk_size": CHUNK_SIZE},
        "manifest_policy": {"encrypted": True, "store_original_paths": False, "filename_policy": "encrypted"},
        "payload_layout": {"chunk_count": len(chunks), "payload_offset": 0, "footer_offset": 0},
        "wrappers": [wrapper], "header_auth": {"algorithm": "HMAC-SHA256"},
    }
    header["header_auth"]["tag"] = _b64(hmac.new(mek, b"HSE2:header-auth:v1" + _canonical(header), hashlib.sha256).digest())
    encoded = _canonical(header)
    target = Path(path)
    with target.open("wb") as out:
        out.write(PREAMBLE.pack(b"HSE2", 3, 1, 0, len(encoded)))
        out.write(encoded)
        out.write(MANIFEST_PREFIX.pack(b"MNF3", len(manifest_ct)))
        out.write(mn + manifest_ct + manifest_tag)
        for index, nonce, ciphertext, tag in chunks:
            out.write(CHUNK_PREFIX.pack(b"CHK3", index, len(ciphertext)))
            out.write(nonce + ciphertext + tag)


def read_archive(path: str | os.PathLike[str], keyfile: bytes) -> dict[str, bytes]:
    """Authenticate and decrypt a documented v3 keyfile archive independently."""
    with Path(path).open("rb") as src:
        pre = src.read(PREAMBLE.size)
        if len(pre) != PREAMBLE.size:
            raise ValueError("truncated preamble")
        magic, version, encoding, reserved, header_len = PREAMBLE.unpack(pre)
        if (magic, version, encoding, reserved) != (b"HSE2", 3, 1, 0) or not 0 < header_len <= 1024 * 1024:
            raise ValueError("invalid v3 preamble")
        raw_header = src.read(header_len)
        if len(raw_header) != header_len:
            raise ValueError("truncated header")
        header = json.loads(raw_header.decode("utf-8"))
        if _canonical(header) != raw_header:
            raise ValueError("noncanonical header")
        dek, mek = _header_keys(header, keyfile)
        prefix = src.read(MANIFEST_PREFIX.size)
        if len(prefix) != MANIFEST_PREFIX.size:
            raise ValueError("truncated manifest prefix")
        marker, length = MANIFEST_PREFIX.unpack(prefix)
        if marker != b"MNF3" or not 0 < length <= 64 * 1024 * 1024:
            raise ValueError("invalid manifest framing")
        mn, ciphertext, tag = src.read(12), src.read(length), src.read(16)
        if len(mn) != 12 or len(ciphertext) != length or len(tag) != 16:
            raise ValueError("truncated manifest")
        mc = AES.new(mek, AES.MODE_GCM, nonce=mn)
        mc.update(b"HSE2:manifest:v1")
        manifest = json.loads(mc.decrypt_and_verify(ciphertext, tag).decode("utf-8"))
        layout = header["payload_layout"]
        chunk_size = header["cipher_suite"]["chunk_size"]
        if layout["payload_offset"] != 0 or layout["footer_offset"] != 0 or layout["chunk_count"] > 2**64 - 1:
            raise ValueError("invalid payload layout")
        plain_chunks = []
        for expected in range(layout["chunk_count"]):
            prefix = src.read(CHUNK_PREFIX.size)
            if len(prefix) != CHUNK_PREFIX.size:
                raise ValueError("truncated chunk prefix")
            marker, index, length = CHUNK_PREFIX.unpack(prefix)
            if marker != b"CHK3" or index != expected or not 0 < length <= min(chunk_size, 16 * 1024 * 1024):
                raise ValueError("invalid chunk framing")
            nonce, ciphertext, tag = src.read(12), src.read(length), src.read(16)
            if len(nonce) != 12 or len(ciphertext) != length or len(tag) != 16:
                raise ValueError("truncated chunk")
            cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)
            cipher.update(f"HSE2:payload-chunk:v1:{index}".encode("ascii"))
            plain_chunks.append(cipher.decrypt_and_verify(ciphertext, tag))
        if src.read(1):
            raise ValueError("trailing bytes")
    restored: dict[str, bytes] = {}
    for entry in manifest["entries"]:
        if entry["kind"] == "directory":
            continue
        item = next(r for r in manifest["payload_ranges"] if r["path"] == entry["path"])
        data = b"".join(plain_chunks[item["start_chunk"]:item["start_chunk"] + item["chunk_count"]])
        if len(data) != item["size"] or item["size"] != entry["size"]:
            raise ValueError("payload range size mismatch")
        restored[entry["path"]] = data
    return restored
