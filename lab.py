#!/usr/bin/env python3
"""Standalone hybrid ML-KEM-768/X25519 key rotation lab (synthetic data only).

This is NOT the E-Office production format, OpenBao integration, or a FIPS-validated service.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

from native_kem import NativeMLKEM768, KemError

MAGIC = "MLKEM-ROTATION-LAB-ONLY-v1"
SUITE = "LAB-MLKEM768-X25519-SHA3-256-HKDFSHA256-AES256KW-v1"
LABEL = bytes.fromhex("5c2e2f2f5e5c")
CHUNK_SIZE = 1024 * 1024
WRAPPED_LEN = 1088 + 32 + 40
POSITION = "DEMO-OFFICE-HEAD"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def lp(data: bytes) -> bytes:
    """LAB-ONLY encoding; not claimed byte-compatible with E-Office."""
    if len(data) > 2**32 - 1:
        raise ValueError("Length prefix overflow")
    return struct.pack(">I", len(data)) + data


def context(doc_id: str, version: int, position: str, key_version: int) -> bytes:
    return b"".join([
        lp(doc_id.encode()), lp(str(version).encode()),
        lp(position.encode()), lp(str(key_version).encode())
    ])


def wrap_key(ss_kem: bytes, ss_x: bytes, ephemeral_pub: bytes,
             recipient_xpub: bytes, doc_id: str, version: int,
             position: str, key_version: int) -> bytes:
    ss = hashlib.sha3_256(ss_kem + ss_x + ephemeral_pub + recipient_xpub + LABEL).digest()
    info = lp(SUITE.encode()) + lp(context(doc_id, version, position, key_version))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ss)


def write_atomic(path: Path, data: bytes, *, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(tmp, flags, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def write_json(path: Path, obj: dict, *, private=False):
    write_atomic(path, canonical(obj) + b"\n", private=private)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while buf := f.read(1024 * 1024):
            h.update(buf)
    return h.hexdigest()


def guard(base: Path):
    marker = base / ".lab-marker.json"
    if not marker.is_file() or read_json(marker).get("magic") != MAGIC:
        raise RuntimeError(f"Not a lab-generated workspace: {base}. Refusing operation.")
    for sub in (base / "records", base / "keys", base / "files"):
        if not sub.is_dir() or sub.is_symlink():
            raise RuntimeError(f"Missing or unsafe workspace directory: {sub}")


def journal(base: Path, action: str, **fields):
    entry = {"time": now(), "event": action, **fields}
    with (base / "events.jsonl").open("ab") as f:
        f.write(canonical(entry) + b"\n")


def generate_keys(kem: NativeMLKEM768, version: int) -> dict:
    private_pem, public_pem = kem.generate()
    xpriv = x25519.X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    return {
        "format": MAGIC, "key_version": version, "suite": SUITE,
        "mlkem_private_pem": private_pem.decode("ascii"),
        "mlkem_public_pem": public_pem.decode("ascii"),
        "x25519_private": b64(xpriv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "x25519_public": b64(xpriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "created_at": now(),
        "security_note": "LAB ONLY: private keys unencrypted on disk; never production",
    }


def load_keys(base: Path, version: int) -> dict:
    p = base / "keys" / f"key_v{version}.json"
    if not p.is_file() or p.is_symlink():
        raise RuntimeError(f"Key version {version} missing, cannot decrypt")
    k = read_json(p)
    if k.get("format") != MAGIC or k.get("key_version") != version:
        raise RuntimeError("Key file invalid")
    return k


def _elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000


def encapsulate_dek(kem: NativeMLKEM768, key: dict, dek: bytes,
                     doc_id: str, version: int, *, metrics: dict | None = None) -> bytes:
    """Encrypt DEK for a recipient; optional phase timings include Python/native boundary overhead."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    t_total = time.perf_counter_ns()
    t = time.perf_counter_ns()
    ct, skem = kem.encapsulate(key["mlkem_public_pem"].encode())
    kem_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    xp = x25519.X25519PublicKey.from_public_bytes(unb64(key["x25519_public"]))
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sx = eph.exchange(xp)
    if sx == b"\x00" * 32:
        raise RuntimeError("Invalid X25519 shared secret")
    x25519_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    kek = wrap_key(skem, sx, eph_pub, unb64(key["x25519_public"]),
                   doc_id, version, POSITION, key["key_version"])
    kdf_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    wrapped = ct + eph_pub + aes_key_wrap(kek, dek)
    kw_ms = _elapsed_ms(t)
    if len(wrapped) != WRAPPED_LEN:
        raise RuntimeError("Unexpected wrapped length")
    if metrics is not None:
        metrics.update({
            "mlkem_encapsulation_ms": kem_ms,
            "x25519_ephemeral_ms": x25519_ms,
            "sha3_hkdf_ms": kdf_ms,
            "aes_kw_wrap_ms": kw_ms,
            "total_ms": _elapsed_ms(t_total),
        })
    return wrapped


def decapsulate_dek(kem: NativeMLKEM768, key: dict, wrapped: bytes,
                     doc_id: str, version: int, *, metrics: dict | None = None) -> bytes:
    """Recover DEK with sk (KEM decap, ECDH, KDF, AES-KW unwrap)."""
    t_total = time.perf_counter_ns()
    if len(wrapped) != WRAPPED_LEN:
        raise ValueError("Wrapped DEK malformed")
    ct, eph_pub, kw = wrapped[:1088], wrapped[1088:1120], wrapped[1120:]
    t = time.perf_counter_ns()
    skem = kem.decapsulate(key["mlkem_private_pem"].encode(), ct)
    kem_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    xp = x25519.X25519PrivateKey.from_private_bytes(unb64(key["x25519_private"]))
    sx = xp.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    if sx == b"\x00" * 32:
        raise RuntimeError("Invalid X25519 shared secret")
    x25519_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    kek = wrap_key(skem, sx, eph_pub, unb64(key["x25519_public"]),
                   doc_id, version, POSITION, key["key_version"])
    kdf_ms = _elapsed_ms(t)
    t = time.perf_counter_ns()
    dek = aes_key_unwrap(kek, kw)
    kw_ms = _elapsed_ms(t)
    if len(dek) != 32:
        raise RuntimeError("Unexpected DEK size")
    if metrics is not None:
        metrics.update({
            "mlkem_decapsulation_ms": kem_ms,
            "x25519_agreement_ms": x25519_ms,
            "sha3_hkdf_ms": kdf_ms,
            "aes_kw_unwrap_ms": kw_ms,
            "total_ms": _elapsed_ms(t_total),
        })
    return dek


def header_for(doc_id: str, data_len: int, prefix: bytes) -> dict:
    return {
        "format": MAGIC, "content_alg": "AES-256-GCM-CHUNK-LAB",
        "document_id": doc_id, "version": 1,
        "plaintext_len": data_len, "chunk_size": CHUNK_SIZE,
        "total_chunks": max(1, (data_len + CHUNK_SIZE - 1) // CHUNK_SIZE),
        "nonce_prefix": b64(prefix),
    }


def encrypt_file(data: bytes, dek: bytes, header: dict) -> bytes:
    h = hashlib.sha256(canonical(header)).digest()
    prefix = unb64(header["nonce_prefix"])
    out = bytearray()
    count = header["total_chunks"]
    aes = AESGCM(dek)
    for i in range(count):
        piece = data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        nonce = prefix + struct.pack(">I", i)
        aad = h + struct.pack(">I", i) + bytes([int(i == count - 1)])
        out.extend(aes.encrypt(nonce, piece, aad))
    return bytes(out)


def decrypt_file(ct: bytes, dek: bytes, header: dict) -> bytes:
    if header["format"] != MAGIC or header["content_alg"] != "AES-256-GCM-CHUNK-LAB":
        raise ValueError("Invalid lab content format")
    total = header["plaintext_len"]
    chunk = header["chunk_size"]
    count = header["total_chunks"]
    if chunk != CHUNK_SIZE or count != max(1, (total + CHUNK_SIZE - 1) // CHUNK_SIZE):
        raise ValueError("Chunk configuration invalid")
    prefix = unb64(header["nonce_prefix"])
    if len(prefix) != 8:
        raise ValueError("Nonce prefix invalid")
    h = hashlib.sha256(canonical(header)).digest()
    pos, plaintext = 0, bytearray()
    aes = AESGCM(dek)
    for i in range(count):
        expected_plain = max(0, min(CHUNK_SIZE, total - i * CHUNK_SIZE))
        ciphertext_chunk = ct[pos:pos + expected_plain + 16]
        if len(ciphertext_chunk) != expected_plain + 16:
            raise ValueError("Truncated ciphertext")
        nonce = prefix + struct.pack(">I", i)
        aad = h + struct.pack(">I", i) + bytes([int(i == count - 1)])
        plaintext.extend(aes.decrypt(nonce, ciphertext_chunk, aad))
        pos += expected_plain + 16
    if pos != len(ct) or len(plaintext) != total:
        raise ValueError("Trailing bytes or incorrect plaintext length")
    return bytes(plaintext)


def path_record(base: Path, doc_id: str) -> Path:
    return base / "records" / f"{doc_id}.json"


def path_file(base: Path, doc_id: str) -> Path:
    return base / "files" / f"{doc_id}.enc"


def file_inventory_digest(records: list[dict]) -> str:
    return sha(canonical({r["document_id"]: r["ciphertext_sha256"] for r in records}))


def records_for(base: Path) -> list[dict]:
    paths = sorted((base / "records").glob("DOC-*.json"))
    return [read_json(x) for x in paths]


def check_inventory(base: Path, records: list[dict], manifest: dict, *, actual_file_hash=True):
    if len(records) != manifest["count"]:
        raise RuntimeError(f"Expected {manifest['count']} records, found {len(records)}")
    if file_inventory_digest(records) != manifest["ciphertext_inventory_sha256"]:
        raise RuntimeError("CIPHERTEXT INVENTORY CHANGED since init")
    if actual_file_hash:
        for r in records:
            if file_sha(path_file(base, r["document_id"])) != r["ciphertext_sha256"]:
                raise RuntimeError(f"Ciphertext changed: {r['document_id']}")


def cmd_init(args, kem):
    base = args.dir.resolve()
    if base.exists():
        raise RuntimeError(f"Refusing to initialize an existing directory: {base}")
    if not 1 <= args.files <= 100_000:
        raise ValueError("--files must be between 1 and 100000")
    if not 1 <= args.size_kb <= 2048:
        raise ValueError("--size-kb must be between 1 and 2048")
    base.mkdir(parents=True, mode=0o700)
    for name in ("records", "keys", "files"):
        (base / name).mkdir(mode=0o700)
    write_json(base / ".lab-marker.json", {"magic": MAGIC, "created_at": now()}, private=True)
    k1 = generate_keys(kem, 1)
    write_json(base / "keys" / "key_v1.json", k1, private=True)
    inventory = {}
    started = time.perf_counter()
    for i in range(1, args.files + 1):
        doc_id = f"DOC-{i:05d}"
        # No original plaintext files are stored. Lab generates synthetic bytes in memory.
        prefix_clear = f"SYNTHETIC LAB DOCUMENT {doc_id}\n".encode()
        clear = prefix_clear + os.urandom(max(0, args.size_kb * 1024 - len(prefix_clear)))
        dek = os.urandom(32)
        header = header_for(doc_id, len(clear), os.urandom(8))
        cipher = encrypt_file(clear, dek, header)
        wrapped = encapsulate_dek(kem, k1, dek, doc_id, 1)
        write_atomic(path_file(base, doc_id), cipher)
        record = {
            "format": MAGIC, "suite": SUITE, "document_id": doc_id, "version": 1,
            "position_code": POSITION, "key_version": 1,
            "header": header, "ciphertext_sha256": sha(cipher),
            "plaintext_sha256_for_lab_only": sha(clear),
            "wrapped_dek": b64(wrapped), "wrapped_dek_bytes": len(wrapped),
        }
        write_json(path_record(base, doc_id), record)
        inventory[doc_id] = record["ciphertext_sha256"]
        if i % 200 == 0 or i == args.files:
            print(f"[init] {i}/{args.files} encrypted + wrapped with pk1")
    elapsed = time.perf_counter() - started
    write_json(base / "manifest.json", {
        "magic": MAGIC, "count": args.files, "size_kb_requested": args.size_kb,
        "position_code": POSITION, "active_key_version": 1,
        "state": "INITIALIZED_V1", "created_at": now(),
        "ciphertext_inventory_sha256": sha(canonical(inventory)),
        "initialization_seconds": round(elapsed, 5),
    })
    journal(base, "initialized", count=args.files, elapsed_seconds=round(elapsed, 5))
    print(f"[init] Complete: {args.files} files, {elapsed:.3f}s. workspace={base}")


def cmd_verify(args, kem, *, quiet=False):
    base = args.dir.resolve()
    guard(base)
    manifest = read_json(base / "manifest.json")
    records = records_for(base)
    check_inventory(base, records, manifest, actual_file_hash=False)
    keys = {}
    start = time.perf_counter()
    versions = {}
    for i, r in enumerate(records, 1):
        version = r["key_version"]
        if version not in keys:
            keys[version] = load_keys(base, version)
        if r["position_code"] != POSITION or r["suite"] != SUITE:
            raise RuntimeError("Invalid position or suite")
        wrapped = unb64(r["wrapped_dek"])
        dek = decapsulate_dek(kem, keys[version], wrapped, r["document_id"], r["version"])
        ciphertext = path_file(base, r["document_id"]).read_bytes()
        if sha(ciphertext) != r["ciphertext_sha256"]:
            raise RuntimeError(f"File changed: {r['document_id']}")
        clear = decrypt_file(ciphertext, dek, r["header"])
        if sha(clear) != r["plaintext_sha256_for_lab_only"]:
            raise RuntimeError(f"Plaintext mismatch: {r['document_id']}")
        versions[version] = versions.get(version, 0) + 1
        if not quiet and (i % 200 == 0 or i == len(records)):
            print(f"[verify] {i}/{len(records)} decrypted + sha256 matched")
    elapsed = time.perf_counter() - start
    result = {"verified": len(records), "versions": versions, "seconds": round(elapsed, 5),
              "ciphertext_unchanged": True, "plaintext_sha256_matched": True}
    if not quiet:
        phase = ("verify_before_rotation_seconds" if manifest["state"] == "INITIALIZED_V1" else
                 "verify_after_rotation_seconds" if manifest["state"] == "MIGRATED_V2_PENDING_RETIRE" else
                 "verify_after_retirement_seconds")
        manifest[phase] = round(elapsed, 6)
        write_json(base / "manifest.json", manifest)
        print("[verify] PASS:", json.dumps(result, sort_keys=True))
    return result


def cmd_rotate(args, kem):
    base = args.dir.resolve()
    guard(base)
    m = read_json(base / "manifest.json")
    recs = records_for(base)
    check_inventory(base, recs, m)
    if m["state"] == "RETIRED_V1":
        raise RuntimeError("Old key already retired")
    if not (base / "keys" / "key_v2.json").exists():
        t_key = time.perf_counter_ns()
        k2 = generate_keys(kem, 2)
        keygen_ms = _elapsed_ms(t_key)
        write_json(base / "keys" / "key_v2.json", k2, private=True)
        m["v2_key_generation_ms"] = round(keygen_ms, 6)
        journal(base, "generated_new_key", key_version=2)
        print("[rotate] Generated independent pk2/sk2 (hybrid ML-KEM-768 + X25519)")
    else:
        k2 = load_keys(base, 2)
        print("[rotate] Resuming using existing pk2/sk2")
    k1 = load_keys(base, 1)
    start = time.perf_counter()
    newly = 0
    for r in recs:
        if r["key_version"] == 2:
            continue
        if r["key_version"] != 1:
            raise RuntimeError("Unexpected key version")
        doc_id = r["document_id"]
        t_item = time.perf_counter_ns()
        old_steps: dict = {}
        new_steps: dict = {}
        verify_steps: dict = {}
        # Only DEK is unwrapped; *.enc never decrypted or rewritten during rotate.
        original = decapsulate_dek(kem, k1, unb64(r["wrapped_dek"]),
                                   doc_id, r["version"], metrics=old_steps)
        new_wrapped = encapsulate_dek(kem, k2, original,
                                     doc_id, r["version"], metrics=new_steps)
        rewrap_only_ms = _elapsed_ms(t_item)
        check = decapsulate_dek(kem, k2, new_wrapped,
                                doc_id, r["version"], metrics=verify_steps)
        if check != original:
            raise RuntimeError(f"Rewrap validation failed: {doc_id}")
        # Negative check is excluded from measured normal path and done only for first record.
        if newly == 0:
            try:
                decapsulate_dek(kem, k1, new_wrapped, doc_id, r["version"])
            except Exception:
                print("[rotate] Negative test PASS: sk1 cannot unwrap wrapped_DEK_v2")
            else:
                raise RuntimeError("Negative test FAILED: old key opened new wrapped DEK")
        elapsed_crypto = _elapsed_ms(t_item)
        new_record = dict(r)
        new_record["wrapped_dek"] = b64(new_wrapped)
        new_record["key_version"] = 2
        timings = {
            "old_sk1": old_steps,
            "new_pk2": new_steps,
            "verify_sk2": verify_steps,
            "unwrap_to_rewrap_ms": rewrap_only_ms,
            # excludes record I/O, negative test (first item) and progress logging
            "crypto_until_verified_ms": elapsed_crypto,
        }
        # Stage timing is embedded in the same atomic record as the new wrapped DEK.
        # This supports resume and avoids a timing log desynchronized after a crash.
        new_record["migration_timing_ms"] = timings
        t_io = time.perf_counter_ns()
        write_json(path_record(base, doc_id), new_record)
        io_ms = _elapsed_ms(t_io)
        # Separate per-file I/O timing is journaled only at aggregate level; exact file I/O
        # timing is not persisted because rewriting the record would change the measurement.
        newly += 1
        if newly % 500 == 0 or newly == len(recs):
            journal(base, "migration_checkpoint", newly_migrated_this_run=newly)
            print(f"[rotate] Migrated {newly} items this run; last record I/O ~{io_ms:.3f} ms")
        if args.stop_after and newly >= args.stop_after:
            journal(base, "interrupted_test", migrated_this_run=newly)
            print("[rotate] STOPPED intentionally. Resume by running rotate again.")
            return
    all_after = records_for(base)
    check_inventory(base, all_after, m)
    if any(x["key_version"] != 2 for x in all_after):
        raise RuntimeError("Migration incomplete")
    elapsed = time.perf_counter() - start
    m["active_key_version"] = 2
    m["state"] = "MIGRATED_V2_PENDING_RETIRE"
    m["rotation_last_run_seconds"] = round(elapsed, 6)
    m["rotation_last_run_items"] = newly
    m["migrated_at"] = now()
    write_json(base / "manifest.json", m)
    journal(base, "migration_complete", count=m["count"], elapsed_seconds=round(elapsed, 6))
    print(f"[rotate] COMPLETE: {m['count']} records bound to pk2/sk2; *.enc unchanged; {elapsed:.3f}s")


def cmd_retire(args, kem):
    base = args.dir.resolve()
    guard(base)
    if not args.confirm_destroy_old:
        raise RuntimeError("Refusing to delete old key without --confirm-destroy-old")
    m = read_json(base / "manifest.json")
    old = base / "keys" / "key_v1.json"
    if m["state"] not in ("MIGRATED_V2_PENDING_RETIRE", "RETIRED_V1"):
        raise RuntimeError("All records must be migrated before old key retirement")
    recs = records_for(base)
    check_inventory(base, recs, m)
    if any(r["key_version"] != 2 for r in recs):
        raise RuntimeError("DEPENDENCIES REMAIN: old key cannot be retired")
    verify = cmd_verify(args, kem, quiet=True)
    m["retirement_verification_seconds"] = verify["seconds"]
    if verify["verified"] != m["count"]:
        raise RuntimeError("Verification incomplete")
    if old.is_symlink():
        raise RuntimeError("Old key path is a symlink")
    if old.exists():
        old.unlink()  # Logical deletion only: NOT cryptographic/physical secure erasure.
        print("[retire] Removed keys/key_v1.json (logical deletion, not secure erase)")
    else:
        print("[retire] keys/key_v1.json was already absent")
    m["state"] = "RETIRED_V1"
    m["retired_at"] = now()
    write_json(base / "manifest.json", m)
    journal(base, "retired_old_key", verified=m["count"], note="logical delete only")
    print(f"[retire] PASS: verified {m['count']} files through sk2; sk1 and pk1 files absent")


def cmd_audit(args, kem):
    base = args.dir.resolve()
    guard(base)
    m = read_json(base / "manifest.json")
    recs = records_for(base)
    check_inventory(base, recs, m)
    result = cmd_verify(args, kem, quiet=True)
    m["audit_verification_seconds"] = result["seconds"]
    write_json(base / "manifest.json", m)
    exists_v1 = (base / "keys" / "key_v1.json").exists()
    exists_v2 = (base / "keys" / "key_v2.json").exists()
    report = {
        "generated_at": now(), "experiment": MAGIC,
        "expected_files": m["count"], "verified_files": result["verified"],
        "versions": result["versions"], "initialization_seconds": m["initialization_seconds"],
        "last_rotation_run_seconds": m.get("rotation_last_run_seconds"),
        "final_verification_seconds": result["seconds"],
        "initial_ciphertext_inventory_sha256": m["ciphertext_inventory_sha256"],
        "current_ciphertext_inventory_sha256": file_inventory_digest(recs),
        "ciphertext_bitwise_unchanged": True,
        "key_v1_file_exists": exists_v1, "key_v2_file_exists": exists_v2,
        "state": m["state"],
        "passed": (result["verified"] == m["count"] and
                   (m["state"] != "RETIRED_V1" or (not exists_v1 and exists_v2))),
        "warning": "Only logical key-file deletion; no claims of SSD erasure, FIPS validation or E-Office interoperability",
    }
    write_json(base / "RESULTS.json", report)
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise RuntimeError("Audit failed")


def _quantile(values, p):
    values = sorted(values)
    if not values:
        return 0.0
    # nearest-rank percentile for transparent reproducibility
    return values[max(0, math.ceil(len(values) * p) - 1)]


def cmd_report(args, kem=None):
    """Generate human-readable TXT table from per-file persisted timings, no cryptographic calls."""
    base = args.dir.resolve()
    guard(base)
    m = read_json(base / "manifest.json")
    recs = records_for(base)
    if len(recs) != m["count"]:
        raise RuntimeError("Incomplete inventory; report requires all records")
    if m["state"] != "RETIRED_V1":
        raise RuntimeError("Complete rotate, verify, retire, audit before final report")
    if (base / "keys" / "key_v1.json").exists() or not (base / "keys" / "key_v2.json").exists():
        raise RuntimeError("Retirement key-state check failed")
    if any(r.get("key_version") != 2 or "migration_timing_ms" not in r for r in recs):
        raise RuntimeError("Incomplete per-document timing history")
    check_inventory(base, recs, m, actual_file_hash=True)
    results = read_json(base / "RESULTS.json")
    if not results.get("passed") or results.get("verified_files") != m["count"]:
        raise RuntimeError("Final audit missing/failed")
    out = base / "LAPORAN_WAKTU_ROTASI_10000.txt"
    columns = [
        ("NO", 5), ("DOCUMENT_ID", 13), ("SK1-KEM", 9), ("SK1-X25519", 11),
        ("SK1-KDF", 9), ("SK1-UNWRAP", 11), ("BUKA-SK1", 10),
        ("PK2-KEM", 9), ("PK2-X25519", 11), ("PK2-KDF", 9),
        ("PK2-WRAP", 10), ("BUNGKUS-PK2", 12), ("REWRAP-SK1-PK2", 16),
        ("VERIFY-SK2", 11), ("TOTAL-KRIPTO", 13),
    ]
    keys = [
        lambda t: t["old_sk1"]["mlkem_decapsulation_ms"],
        lambda t: t["old_sk1"]["x25519_agreement_ms"],
        lambda t: t["old_sk1"]["sha3_hkdf_ms"],
        lambda t: t["old_sk1"]["aes_kw_unwrap_ms"],
        lambda t: t["old_sk1"]["total_ms"],
        lambda t: t["new_pk2"]["mlkem_encapsulation_ms"],
        lambda t: t["new_pk2"]["x25519_ephemeral_ms"],
        lambda t: t["new_pk2"]["sha3_hkdf_ms"],
        lambda t: t["new_pk2"]["aes_kw_wrap_ms"],
        lambda t: t["new_pk2"]["total_ms"],
        lambda t: t["unwrap_to_rewrap_ms"],
        lambda t: t["verify_sk2"]["total_ms"],
        lambda t: t["crypto_until_verified_ms"],
    ]
    vals = [[f(t) for t in (r["migration_timing_ms"] for r in recs)] for f in keys]
    def line(parts):
        return " | ".join(str(part).ljust(width) for part, (_, width) in zip(parts, columns)).rstrip() + "\n"
    with out.open("w", encoding="utf-8") as f:
        f.write("LAPORAN WAKTU ROTASI 10.000 FILE — LAB ML-KEM-768 + X25519\n")
        f.write("=" * 150 + "\n")
        f.write(f"Generated UTC     : {now()}\n")
        f.write(f"Workspace         : {base}\n")
        f.write(f"Jumlah file       : {m['count']:,}\n")
        f.write(f"Ukuran sintetis   : {m['size_kb_requested']} KiB / file\n")
        f.write(f"Status akhir      : {m['state']}\n")
        f.write("Kunci aktif       : pk2/sk2; kunci v1 tidak ada sebagai file lab\n")
        f.write("Satuan tabel      : milidetik (ms)\n")
        f.write("SK1: ML-KEM decaps + X25519 + SHA3/HKDF + AES-KW unwrap\n")
        f.write("PK2: ML-KEM encaps + X25519 ephemeral + SHA3/HKDF + AES-KW wrap\n")
        f.write("REWRAP-SK1-PK2: total buka DEK dengan sk1 hingga selesai membungkus DEK dengan pk2 (tanpa verifikasi).\n")
        f.write("VERIFY-SK2: decaps + unwrap lagi untuk memeriksa DEK identik\n")
        f.write("TOTAL-KRIPTO: durasi proses kriptografi per item sebelum I/O commit (termasuk negative test pada baris pertama).\n")
        f.write("Waktu total ROTATE nyata termasuk I/O, flush disk, pembacaan inventaris, progres, dan overhead Python.\n")
        f.write("\nRINGKASAN WAKTU (waktu tembok/wall clock, detik)\n")
        periods = [
            ("Pembangkitan 10.000 file v1 + enkripsi", "initialization_seconds"),
            ("Verifikasi awal melalui sk1", "verify_before_rotation_seconds"),
            ("Pembangkitan pasangan pk2/sk2 (ms)", "v2_key_generation_ms"),
            ("ROTASI 10.000 wrapped DEK (termasuk I/O)", "rotation_last_run_seconds"),
            ("Verifikasi seluruh file dengan sk2", "verify_after_rotation_seconds"),
            ("Verifikasi prapenghapusan kunci v1", "retirement_verification_seconds"),
            ("Audit akhir seluruh file", "audit_verification_seconds"),
        ]
        for label, k in periods:
            value = m.get(k)
            unit = "ms" if k.endswith("_ms") else "s"
            f.write(f"  {label:48s} : {value if value is not None else 'n/a'} {unit}\n")
        if args.wall_start_epoch is not None:
            f.write(f"  TOTAL WALL-CLOCK PIPELINE                      : {max(0,time.time() - args.wall_start_epoch):.6f} s\n")
            f.write("  (termasuk self-test, init, verify, rotate, retire, audit; hingga awal pembuatan laporan)\n")
        else:
            f.write("  TOTAL WALL-CLOCK PIPELINE                      : tidak tersedia (gunakan run_all.sh)\n")
        f.write("\nAGREGAT TAHAP KRIPTO PER ITEM (milidetik)\n")
        names = ["sk1 kem", "sk1 x25519", "sk1 kdf", "sk1 unwrap", "Buka sk1 total",
                 "pk2 kem", "pk2 x25519", "pk2 kdf", "pk2 wrap", "Bungkus pk2 total",
                 "Rewrap sk1 ke pk2", "Verifikasi sk2", "Kripto lengkap per file"]
        f.write(f"  {'Tahap':27s} {'Jumlah ms':>14s} {'Mean ms':>12s} {'Median ms':>12s} {'P95 ms':>12s} {'P99 ms':>12s}\n")
        for name, arr in zip(names, vals):
            f.write(f"  {name:27s} {sum(arr):14.3f} {sum(arr)/len(arr):12.4f} {_quantile(arr,.5):12.4f} {_quantile(arr,.95):12.4f} {_quantile(arr,.99):12.4f}\n")
        f.write("\nTABEL RINCI PER FILE (SELURUH 10.000 FILE)\n")
        f.write(line([h for h, _ in columns]))
        f.write("-" * (sum(width for _, width in columns) + 3*(len(columns)-1)) + "\n")
        for i, r in enumerate(recs, 1):
            t = r["migration_timing_ms"]
            f.write(line([f"{i:05d}", r["document_id"]] + [f"{func(t):.3f}" for func in keys]))
        f.write("\nPENGECEKAN KEAMANAN DAN KETERBATASAN\n")
        f.write(f" - Seluruh ciphertext tetap sama (SHA-256): {results.get('ciphertext_bitwise_unchanged')}\n")
        f.write(f" - Jumlah file berhasil diverifikasi: {results['verified_files']}/{m['count']}\n")
        f.write(f" - File key_v1.json masih ada: {results['key_v1_file_exists']}\n")
        f.write(f" - File key_v2.json tersedia: {results['key_v2_file_exists']}\n")
        f.write(" - Penghapusan kunci v1 bersifat LOGIS, tidak menjamin sanitasi media penyimpanan.\n")
        f.write(" - Bukan benchmark AWS-LC/OpenBao/E-Office; operasi KEM via OpenSSL 3.5+ EVP.\n")
        f.write(" - Waktu per file adalah wall-clock lokal serial, bukan waktu CPU native murni.\n")
        f.write(" - Total tahap rinci tidak otomatis sama dengan total rotasi, karena ada I/O dan overhead.\n")
        f.write(" - Key plaintext tersimpan dalam file JSON untuk eksperimen saja, JANGAN untuk data produksi.\n")
    print(f"[report] TXT created: {out}")
    print(f"[report] Measured rows: {len(recs)}; rotate wall: {m.get('rotation_last_run_seconds')} s")


def cmd_self_test(kem):
    key = generate_keys(kem, 1)
    original = os.urandom(32)
    wrapped = encapsulate_dek(kem, key, original, "DOC-TEST", 1)
    assert decapsulate_dek(kem, key, wrapped, "DOC-TEST", 1) == original
    # Binding to document_id: context mismatch must fail AES-KW integrity.
    try:
        decapsulate_dek(kem, key, wrapped, "DOC-DIFFERENT", 1)
    except Exception:
        pass
    else:
        raise RuntimeError("Document-context substitution was not detected")
    # A flipped wrapped ciphertext byte must be rejected on unwrap.
    broken = bytearray(wrapped)
    broken[-1] ^= 1
    try:
        decapsulate_dek(kem, key, bytes(broken), "DOC-TEST", 1)
    except Exception:
        pass
    else:
        raise RuntimeError("Tampered wrapped DEK was not detected")
    clear = os.urandom(CHUNK_SIZE + 123)
    h = header_for("DOC-TEST", len(clear), os.urandom(8))
    ct = encrypt_file(clear, original, h)
    assert decrypt_file(ct, original, h) == clear
    wrong_header = dict(h)
    wrong_header["document_id"] = "DOC-WRONG"
    try:
        decrypt_file(ct, original, wrong_header)
    except InvalidTag:
        pass
    else:
        raise RuntimeError("Header swap was not detected")
    try:
        decrypt_file(ct[:-1], original, h)
    except (InvalidTag, ValueError):
        pass
    else:
        raise RuntimeError("Truncation was not detected")
    print("SELF-TEST PASS: real ML-KEM-768, hybrid wrap/unwrap, context tamper, AES-GCM multi-chunk, truncation rejection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "verify", "rotate", "retire", "audit", "report"):
        p = sub.add_parser(command)
        p.add_argument("--dir", type=Path, required=True, help="Dedicated synthetic lab workspace")
        if command == "init":
            p.add_argument("--files", type=int, default=1000)
            p.add_argument("--size-kb", type=int, default=4)
        if command == "rotate":
            p.add_argument("--stop-after", type=int, default=0, help="Intentionally pause after N migrated items")
        if command == "retire":
            p.add_argument("--confirm-destroy-old", action="store_true")
        if command == "report":
            p.add_argument("--wall-start-epoch", type=float, default=None,
                           help="Epoch seconds recorded at start of full pipeline")
    sub.add_parser("self-test")
    args = parser.parse_args()
    kem = None if args.command == "report" else NativeMLKEM768()
    handler = {
        "init": cmd_init, "verify": cmd_verify, "rotate": cmd_rotate,
        "retire": cmd_retire, "audit": cmd_audit, "report": cmd_report,
        "self-test": cmd_self_test,
    }[args.command]
    handler(args, kem) if args.command != "self-test" else handler(kem)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KemError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
