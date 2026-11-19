"""Minimal OpenSSL 3.5 EVP/PKEY binding for a standalone ML-KEM-768 lab.

This is a test utility, not an audited general-purpose crypto library.
Keys are exchanged with this module in PKCS#8/SPKI PEM formats.
"""
from __future__ import annotations

import os
import ctypes as C
from ctypes import util


class KemError(RuntimeError):
    pass


class NativeMLKEM768:
    CT_LENGTH = 1088
    SS_LENGTH = 32

    def __init__(self):
        # The `openssl` command and the shared library chosen by ctypes may
        # come from different installations. Prefer an explicit full path in
        # MLKEM_LIBCRYPTO when Ubuntu/WSL has more than one OpenSSL installed.
        name = os.environ.get("MLKEM_LIBCRYPTO") or util.find_library("crypto")
        if not name:
            raise KemError("libcrypto not found; OpenSSL 3.5+ is required")
        try:
            self.lib = C.CDLL(name)
        except OSError as exc:
            raise KemError(f"Cannot load libcrypto {name!r}: {exc}") from exc
        self._configure()
        ver = self._openssl_version_num()
        if ver < 0x30500000:
            raise KemError(
                f"OpenSSL 3.5+ required; loaded {name!r} libcrypto version: 0x{ver:x}. "
                "`openssl version` only checks the CLI. Find its actual library "
                "with `ldd $(command -v openssl) | grep libcrypto`; then set "
                "MLKEM_LIBCRYPTO=/absolute/path/to/libcrypto.so.3. "
                "Do not replace system-wide libcrypto."
            )

    def _configure(self):
        P = C.c_void_p
        I = C.c_int
        Z = C.c_size_t
        self._openssl_version_num = self._bind("OpenSSL_version_num", C.c_ulong, [])
        self._ctx_from_name = self._bind("EVP_PKEY_CTX_new_from_name", P, [P, C.c_char_p, C.c_char_p])
        self._keygen_init = self._bind("EVP_PKEY_keygen_init", I, [P])
        self._generate = self._bind("EVP_PKEY_generate", I, [P, C.POINTER(P)])
        self._pkey_free = self._bind("EVP_PKEY_free", None, [P])
        self._ctx_free = self._bind("EVP_PKEY_CTX_free", None, [P])
        self._bio_s_mem = self._bind("BIO_s_mem", P, [])
        self._bio_new = self._bind("BIO_new", P, [P])
        self._bio_read = self._bind("BIO_read", I, [P, P, I])
        self._bio_ctrl = self._bind("BIO_ctrl", C.c_long, [P, I, C.c_long, P])
        self._bio_free = self._bind("BIO_free", I, [P])
        self._bio_new_mem_buf = self._bind("BIO_new_mem_buf", P, [P, I])
        self._pem_write_priv = self._bind("PEM_write_bio_PrivateKey", I, [P, P, P, P, I, P, P])
        self._pem_write_pub = self._bind("PEM_write_bio_PUBKEY", I, [P, P])
        self._pem_read_priv = self._bind("PEM_read_bio_PrivateKey", P, [P, P, P, P])
        self._pem_read_pub = self._bind("PEM_read_bio_PUBKEY", P, [P, P, P, P])
        self._ctx_from_key = self._bind("EVP_PKEY_CTX_new", P, [P, P])
        self._enc_init = self._bind("EVP_PKEY_encapsulate_init", I, [P, P])
        self._enc = self._bind("EVP_PKEY_encapsulate", I, [P, P, C.POINTER(Z), P, C.POINTER(Z)])
        self._dec_init = self._bind("EVP_PKEY_decapsulate_init", I, [P, P])
        self._dec = self._bind("EVP_PKEY_decapsulate", I, [P, P, C.POINTER(Z), P, Z])

    def _bind(self, name, restype, argtypes):
        fn = getattr(self.lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
        return fn

    @staticmethod
    def _must(ok: bool, label: str):
        if not ok:
            raise KemError(f"OpenSSL EVP failed: {label}")

    def _write_pem(self, key, private: bool) -> bytes:
        bio = self._bio_new(self._bio_s_mem())
        self._must(bool(bio), "BIO_new")
        try:
            ret = (self._pem_write_priv(bio, key, None, None, 0, None, None)
                   if private else self._pem_write_pub(bio, key))
            self._must(ret == 1, "PEM_write")
            available = self._bio_ctrl(bio, 10, 0, None)  # BIO_CTRL_PENDING
            self._must(available > 0, "BIO_ctrl")
            out = C.create_string_buffer(available)
            self._must(self._bio_read(bio, out, available) == available, "BIO_read")
            return out.raw
        finally:
            self._bio_free(bio)

    def generate(self) -> tuple[bytes, bytes]:
        ctx = self._ctx_from_name(None, b"ML-KEM-768", None)
        self._must(bool(ctx), "CTX_new_from_name")
        key = C.c_void_p()
        try:
            self._must(self._keygen_init(ctx) == 1, "keygen_init")
            self._must(self._generate(ctx, C.byref(key)) == 1, "keygen")
            return self._write_pem(key, True), self._write_pem(key, False)
        finally:
            if key.value:
                self._pkey_free(key)
            self._ctx_free(ctx)

    def _load_key(self, pem: bytes, private: bool):
        buf = C.create_string_buffer(pem)
        bio = self._bio_new_mem_buf(buf, len(pem))
        self._must(bool(bio), "BIO_new_mem_buf")
        try:
            key = (self._pem_read_priv(bio, None, None, None)
                   if private else self._pem_read_pub(bio, None, None, None))
            self._must(bool(key), "PEM_read_bio_key")
            return key
        finally:
            self._bio_free(bio)

    def encapsulate(self, public_pem: bytes) -> tuple[bytes, bytes]:
        key = self._load_key(public_pem, private=False)
        ctx = self._ctx_from_key(key, None)
        try:
            self._must(bool(ctx), "EVP_PKEY_CTX_new")
            self._must(self._enc_init(ctx, None) == 1, "encapsulate_init")
            ct_len, ss_len = C.c_size_t(), C.c_size_t()
            self._must(self._enc(ctx, None, C.byref(ct_len), None, C.byref(ss_len)) == 1, "encapsulate_lengths")
            self._must(ct_len.value == self.CT_LENGTH and ss_len.value == self.SS_LENGTH, "unexpected KEM output lengths")
            ct, ss = C.create_string_buffer(ct_len.value), C.create_string_buffer(ss_len.value)
            self._must(self._enc(ctx, ct, C.byref(ct_len), ss, C.byref(ss_len)) == 1, "encapsulate")
            return ct.raw[:ct_len.value], ss.raw[:ss_len.value]
        finally:
            if ctx:
                self._ctx_free(ctx)
            self._pkey_free(key)

    def decapsulate(self, private_pem: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.CT_LENGTH:
            raise KemError("Invalid ML-KEM-768 ciphertext length")
        key = self._load_key(private_pem, private=True)
        ctx = self._ctx_from_key(key, None)
        try:
            self._must(bool(ctx), "EVP_PKEY_CTX_new")
            self._must(self._dec_init(ctx, None) == 1, "decapsulate_init")
            ct = C.create_string_buffer(ciphertext)
            ss_len = C.c_size_t(0)
            self._must(self._dec(ctx, None, C.byref(ss_len), ct, len(ciphertext)) == 1, "decapsulate_length")
            self._must(ss_len.value == self.SS_LENGTH, "unexpected shared-secret size")
            ss = C.create_string_buffer(ss_len.value)
            self._must(self._dec(ctx, ss, C.byref(ss_len), ct, len(ciphertext)) == 1, "decapsulate")
            return ss.raw[:ss_len.value]
        finally:
            if ctx:
                self._ctx_free(ctx)
            self._pkey_free(key)
