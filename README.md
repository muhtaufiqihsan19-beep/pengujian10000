# Eksperimen Rotasi 10.000 Dokumen — ML-KEM-768 + X25519

**Lab sintetis, bukan Crypto Service E-Office produksi.** Eksperimen ini membuat 10.000 file `.enc` dan DEK acak, membungkus masing-masing DEK ke pasangan kunci hybrid v1 (`pk1/sk1`), membuka DEK dengan `sk1`, membungkus ulang dengan `pk2`, memverifikasi dengan `sk2`, dan *baru setelah semua lulus* menghapus file key v1 secara logis. Isi ciphertext `*.enc` tidak ditulis ulang saat rotasi.

**Perubahan utama dari bundle 1.000:** default 10.000 dan output teks rinci `LAPORAN_WAKTU_ROTASI_10000.txt` dengan **10.000 baris waktu per file** serta total keseluruhan (untuk menjalankan perintah otomatis).

## Cara cepat — Ubuntu/WSL

```bash
cd mlkem-rotation-lab-10000
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
chmod +x run_all.sh

# Cek bila terdapat beberapa instalasi OpenSSL:
ldd "$(command -v openssl)" | grep libcrypto
# Sesuaikan dengan PATH valid pada output ldd di komputer Anda, misalnya:
export MLKEM_LIBCRYPTO=/opt/openssl-3.5/lib64/libcrypto.so.3

./run_all.sh
```

**Catatan:** `export MLKEM_LIBCRYPTO=...` hanya diperlukan bila Python tidak otomatis memuat `libcrypto` OpenSSL 3.5+. Jangan mengetik path contoh jika tidak benar-benar ada. Jika konfigurasi OpenSSL berhasil pada bundle v1.1, gunakan konfigurasi yang sama di sini.

Parameter opsional: `./run_all.sh ./lab-10000 10000 4` (folder output, jumlah file, KiB per file).

**Docker:** `chmod +x run_docker.sh && ./run_docker.sh` (butuh Docker tersedia dan aktif).

## Isi hasil

Dalam folder output otomatis `lab-run-YYYYMMDD-HHMMSS/`:

- `LAPORAN_WAKTU_ROTASI_10000.txt` — tabel per file + agregat waktu (hasil utama).
- `RESULTS.json` — hasil audit, versi kunci, jumlah file, hash ciphertext.
- `manifest.json` — metadata durasi setiap fase dan status akhir.
- `records/` — wrapped DEK v2 untuk semua 10.000 dokumen; setiap record juga menyimpan `migration_timing_ms`.
- `files/` — 10.000 ciphertext yang tetap sama saat rewrap.
- `keys/key_v2.json` — key hybrid baru dalam bentuk **plaintext** (KHUSUS LAB).
- `keys/key_v1.json` — *seharusnya tidak ada* setelah proses `retire` berhasil.

**Tabel waktu** berisi: `SK1-KEM`, `SK1-X25519`, `SK1-KDF`, `SK1-UNWRAP`, `BUKA-SK1`, `PK2-KEM`, `PK2-X25519`, `PK2-KDF`, `PK2-WRAP`, `BUNGKUS-PK2`, `REWRAP-SK1-PK2`, `VERIFY-SK2`, `TOTAL-KRIPTO`. Satuan: **milidetik per file**. Header memperlihatkan durasi fase `init`, `verify` awal, `rotate`, `verify` akhir, `retire`, `audit`, serta `TOTAL WALL-CLOCK PIPELINE` untuk `run_all.sh` / `run_docker.sh`.

- `BUKA-SK1` = decapsulation hybrid dan AES-KW **unwrap DEK**, **bukan** dekripsi isi `.enc`.
- `BUNGKUS-PK2` = encapsulation hybrid dan AES-KW **wrap DEK**.
- `REWRAP-SK1-PK2` = total membuka DEK dengan sk1 hingga selesai membungkusnya dengan pk2, tanpa tahap verifikasi.
- `TOTAL-KRIPTO` = buka, bungkus, verifikasi dan overhead kripto; tidak memasukkan I/O persistensi record. Item pertama juga memasukkan tes negatif dengan sk1. `ROTASI ... (termasuk I/O)` adalah waktu dinding keseluruhan `rotate`.
- `TOTAL WALL-CLOCK PIPELINE` = total dari self-test sampai awal pembentukan laporan, termasuk inisialisasi 10.000 file dan seluruh verifikasi. Bukan hanya waktu rewrap.

## Mode manual / lanjutan

```bash
python3 lab.py self-test
python3 lab.py init   --dir ./lab-10000 --files 10000 --size-kb 4
python3 lab.py verify --dir ./lab-10000
python3 lab.py rotate --dir ./lab-10000
python3 lab.py verify --dir ./lab-10000
python3 lab.py retire --dir ./lab-10000 --confirm-destroy-old
python3 lab.py audit  --dir ./lab-10000
python3 lab.py report --dir ./lab-10000
```

Jika manual, kolom `TOTAL WALL-CLOCK PIPELINE` tidak tersedia, tetapi total fase `rotate` dan tabel per file tetap ada. `lab.py rotate --stop-after 500` dapat menguji checkpoint; jalankan ulang tanpa `--stop-after` untuk melanjutkan. Jangan menjalankan `init` ulang di direktori yang sama.

## Batasan keamanan dan metodologi

- Menggunakan **OpenSSL 3.5+ EVP/PKEY** untuk ML-KEM-768, `cryptography` untuk X25519/AES-KW/AES-GCM, bukan AWS-LC/OpenBao.
- Format uji bukan `PKS1`, `JKB1`, `CTS1`, atau `EKS1` milik E-Office. Hasil eksperimen **tidak** membuktikan interoperabilitas atau sertifikasi FIPS 140-3.
- Penghapusan `key_v1.json` adalah **penghapusan logis file**, bukan *secure erase* dari media fisik, salinan memori, backup atau snapshot.
- Setiap record memiliki satu DEK, satu wrapped DEK. Saat rotasi, `.enc` tidak berubah dan tidak didekripsi.
- Kunci privat dalam lab disimpan tanpa enkripsi. **Jangan gunakan data produksi atau kunci sungguhan.**
- Waktu wall-clock bergantung pada CPU, I/O, kinerja WSL, filesystem, versi OpenSSL dan pengaturan mesin. Karena menulis 10.000 file `.enc` dan 10.000 JSON serta memanggil fsync, waktu pipeline bisa jauh lebih besar daripada waktu operasi ML-KEM murni.

**Paket ini disiapkan tanpa menjalankan eksperimen 10.000 file.** Eksekusi dan pengukuran dilakukan pengguna.
