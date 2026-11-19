# Panduan Eksperimen 10.000 File — Rotasi ML-KEM-768/X25519

## A. Tujuan

Membuktikan 10.000 wrapped DEK semula dibuka oleh kunci jabatan hybrid v1 dan setelah operasi rewrap dapat dibuka oleh v2, tanpa mengubah ciphertext AES-GCM pada disk. Laporan harus memuat waktu membuka DEK dengan sk1, mengikat kembali dengan pk2, verifikasi sk2, dan total waktu rotasi/pipeline.

## B. Environment

- Ubuntu 22.04+/WSL2 atau Linux, Python 3.10+, pip, dan OpenSSL **libcrypto 3.5+** (bukan hanya CLI).
- `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- Jika `ERROR: OpenSSL 3.5+ required; libcrypto version: 0x30000020`, gunakan library OpenSSL 3.5 yang sama dengan keberhasilan bundle v1.1.
- Contoh mengidentifikasi lokasi: `ldd "$(command -v openssl)" | grep libcrypto`. Ekspor `MLKEM_LIBCRYPTO=/path/benar/libcrypto.so.3` jika diperlukan.
- Alternatif: Docker, `./run_docker.sh`.

## C. Jalankan seluruhnya

```bash
chmod +x run_all.sh
./run_all.sh
```

Default: **10.000 file sintetis × 4 KiB**. Perintah dapat diubah: `./run_all.sh ./hasil-uji 10000 4`.

Tahapan:

1. Self-test komponen kriptografi.
2. Buat satu pasangan key v1 hybrid untuk satu jabatan sintetis.
3. Buat 10.000 DEK, 10.000 file berisi ciphertext AES-256-GCM, dan 10.000 wrapped DEK untuk pk1.
4. Verifikasi awal bahwa 10.000 file dapat dibuka melalui sk1.
5. Buat pasangan hybrid pk2/sk2 independen.
6. Untuk setiap dokumen: decaps + X25519 + KDF + AES-KW unwrap dengan sk1, encaps + X25519 + KDF + AES-KW wrap dengan pk2, lalu verifikasi menggunakan sk2. Simpan waktu tiap suboperasi dan wrapped DEK v2 dalam record yang diperbarui secara atomik.
7. Verifikasi seluruh file menggunakan sk2 dan bandingkan SHA-256 plaintext dan ciphertext.
8. Periksa tidak ada wrapped DEK yang masih memiliki key_version 1, kemudian hapus **file** `key_v1.json` (logis).
9. Audit akhir seluruh dokumen, kemudian hasilkan laporan teks.

Jika ada kegagalan, script berhenti (set -e). Kunci lama **tidak** dihapus sebelum tahap verifikasi lengkap dan `retire`. Selama proses, file output berada dalam folder khusus yang dibuat baru.

## D. Laporan akhir

Buka `LAPORAN_WAKTU_ROTASI_10000.txt` di dalam folder yang ditampilkan pada terminal. Contoh:

```bash
head -55 lab-run-*/LAPORAN_WAKTU_ROTASI_10000.txt
less -S lab-run-*/LAPORAN_WAKTU_ROTASI_10000.txt
```

Bagian pertama merangkum durasi pipeline, fase rotasi, dan distribusi waktu (rerata, median, P95, P99). Bagian kedua merupakan tabel lengkap 10.000 file dengan seluruh subfase, seluruhnya dalam **ms**.

Makna waktu:
- `SK1-KEM`: waktu OpenSSL native ML-KEM decapsulation, termasuk pemuatan PEM dan FFI.
- `SK1-X25519`: waktu agreement kunci klasik penerima v1.
- `SK1-KDF`: SHA3-256 combiner dan HKDF-SHA256 menggunakan context v1.
- `SK1-UNWRAP`: AES-256-KW unwrap menjadi DEK.
- `PK2-KEM`: waktu OpenSSL native ML-KEM encapsulation, termasuk pemuatan public PEM dan FFI.
- `PK2-X25519`: pembuatan kunci ephemeral dan agreement ke public key v2.
- `PK2-KDF`: combiner dan HKDF menggunakan context versi key v2.
- `PK2-WRAP`: AES-256-KW wrap DEK lama dengan KEK baru.
- `REWRAP-SK1-PK2`: waktu mulai membuka DEK dengan sk1 hingga selesai wrap DEK dengan pk2, sebelum verifikasi.
- `VERIFY-SK2`: decapsulation dan unwrap dengan kunci baru, memastikan DEK sama.
- `TOTAL-KRIPTO`: waktu buka→bungkus→verifikasi per file, termasuk overhead fungsi. Tidak mencakup penyimpanan record.
- `ROTASI ... (termasuk I/O)`: elapsed time proses rotasi seluruh batch, termasuk persistensi record dan pemeriksaan inventaris.
- `TOTAL WALL-CLOCK PIPELINE`: waktu dari sebelum self-test sampai awal pembuatan laporan (untuk script otomatis).

Waktu jumlah semua kolom suboperasi tidak selalu sama persis dengan `TOTAL-KRIPTO`: ada parsing, kontrol, dan overhead lain. Agregat mean/P95/P99 dipakai untuk menemukan fluktuasi atau outlier.

## E. Catatan metodologi

Durasi per-file diukur menggunakan `time.perf_counter_ns()` pada proses Python, mencakup pemanggilan native dan overhead FFI/API. Pengukuran serial pada satu mesin, sehingga bukan *benchmark throughput* untuk sistem produksi multi-worker.

Skenario menggunakan perwakilan **satu jabatan** dan 10.000 wrapped DEK; **bukan 10.000 pasangan kunci berbeda**. Pasangan key v2 dibangkitkan satu kali. Yang dihapus adalah satu file berisi kedua komponen kunci v1.

Tidak ada full re-encryption dari `.enc` pada tahap rotasi. `verify`, `retire` dan `audit` dapat mendekripsi ciphertext untuk membuktikan kebenaran migrasi. Tahap rotasi sendiri hanya mengubah wrapped DEK.

## F. Troubleshooting

- `Permission denied`: `chmod +x run_all.sh` atau `bash run_all.sh`.
- `libcrypto version 0x30000020`: Python memakai OpenSSL 3.0.2, set `MLKEM_LIBCRYPTO` ke path penuh OpenSSL 3.5, atau Docker.
- `Refusing to initialize an existing directory`: ubah nama folder output; jangan timpa dataset lama.
- `Report requires all records` atau incomplete timing: selesaikan tahapan rotasi dan audit dulu.
- `Missing key`: jangan hapus key v1 manual; biarkan `retire` melakukan setelah verifikasi.

## G. Catatan keamanan

Jangan dipakai pada dokumen kantor, key privat nyata, atau data pribadi. Tidak ada OpenBao atau mekanisme sanitasi media. Format file lab bukan format E-Office. Untuk implementasi produksi, dibutuhkan otorisasi rotate, pengelolaan crash consistency dan rollback, *backup and restore*, key lifecycle, dan audit eksternal.
