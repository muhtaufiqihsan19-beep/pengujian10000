# Peta integrasi hasil eksperimen ke Crypto Service E-Office

Berdasarkan dua dokumen E-Office (18 November 2026). **Bukan implementasi
produksi**; langkah di bawah membutuhkan perubahan kode dan review keamanan.

## 1. Yang sudah tersedia pada desain

- Suite v2: ML-KEM-768 + X25519; combiner SHA3-256; HKDF-SHA256 dengan context;
  AES-256-KW untuk DEK; ciphertext AES-256-GCM per chunk.
- Penyimpanan di E-Office: `position_keys` dengan `(position_code,key_version)`
  dan `document_keys` dengan `wrapped_key` per penerima dan versi dokumen.
- Backend custody: private key jabatan berada dalam `private_key_blob` yang
  di-seal OpenBao, di-unseal pada permintaan yang berwenang.
- Endpoint `POST /dispositions` telah melakukan unwrap lalu wrap ke penerima
  lain. Namun endpoint ini melarang target dengan `position_code` yang sama,
  termasuk key_version berbeda. Ia **bukan** endpoint rotasi.

## 2. Perubahan yang diperlukan untuk rotasi

### API admin yang terautorisasi

Usulkan:

- `POST /key-rotations`: memulai job untuk `(position_code, old_key_id,
  new_key_id)`, hanya setelah ada grant otorisasi administratif.
- `POST /key-rotations/{rotation_id}/run`: pekerja batch membaca wrapped DEK v1,
  unseal sk1, unwrap DEK, wrap dengan pk2, verifikasi menggunakan sk2, lalu
  simpan staging record. Jangan streaming plaintext file ke endpoint ini.
- `GET /key-rotations/{rotation_id}`: status `pending`, `running`, `verified`,
  `committed`, `retired`, `failed` dan jumlah item per status.
- `POST /key-rotations/{rotation_id}/commit`: aktivasi v2 dan atomik
  penggantian metadata setelah seluruh record terbukti siap.
- `POST /key-rotations/{rotation_id}/retire`: hanya setelah dependency scan
  dan backup policy memenuhi syarat. Pemusnahan private key v1 perlu
  koordinasi OpenBao dan aplikasi.

API di atas hanyalah **usulan kontrak**, bukan endpoint yang sudah ada.

### Metadata dan database

- `document_keys` pada contoh memakai unique `(document_id,version,position_code)`;
  tidak menyediakan dua wrapped key untuk key version berbeda. Tambahkan
  `(document_id,version,position_code,key_version)` pada model multi-versi,
  atau staging table agar migrasi dapat dibuktikan sebelum commit.
- Gunakan `key_id` immutable yang mengikat fingerprint PKS1, position_code,
  key_version, suite_id, dan status lifecycle. Hindari dua keypair berbeda
  dengan pasangan `(position_code,key_version)` yang sama.
- Pastikan job idempotent dan resumable. Setiap item punya checkpoint,
  correlation ID, dan status audit. Selesaikan transaksi tiap batch terbatas.

### Trust boundary dan OpenBao

- Gunakan OpenBao untuk seal/unseal JKB1. Jangan simpan plaintext private key
  dalam database atau file produksi sebagaimana dilakukan lab.
- Gunakan grant admin khusus rotasi; grant disposisi pengguna tidak cukup.
- Proses *unwrap DEK lama* harus mengikat context lama, sedangkan *wrap DEK
  baru* mengikat context baru termasuk `key_version` baru.
- Jangan mengubah `EKS1` atau `CTS1` karena isi dokumen dan DEK tetap sama.
  Untuk kompromi DEK, gunakan **full re-encryption** secara terpisah.
- Rotasi kunci jabatan tidak sama dengan rotasi KEK Transit OpenBao.
- Key v1 boleh dihapus dari storage aktif hanya setelah bukti backup,
  recovery, seluruh wrapped DEK dan grant/arsip historis diperiksa.

## 3. Gate sebelum penghapusan key lama

1. Semua wrapped DEK aktif yang bergantung pada key v1 telah terinventarisasi.
2. Setiap item memiliki wrapped DEK v2 dan berhasil di-unwrap kembali memakai sk2.
3. Hash ciphertext pada seluruh file tidak berubah.
4. Verifikasi decrypt file sampel dan, jika diperlukan, seluruh data lulus.
5. Tidak ada job in-flight yang masih harus memakai sk1.
6. Backup, snapshot, kunci arsip dan prosedur recovery disetujui pemilik sistem.
7. Otorisasi perubahan key status telah disahkan dan tercatat.
8. Pemusnahan dilakukan sesuai kebijakan media dan retensi, bukan sekadar
   `rm` pada file produksi.

## 4. Pengujian lanjutan untuk source code asli

- 1.000 wrapped DEK per jabatan, 10.000, lalu 100.000.
- Fault injection setelah 1/10/50/99% item diproses.
- Dua worker memigrasikan item yang sama (optimistic locking).
- Key v1 dicabut di tengah proses: job harus berhenti aman.
- OpenBao timeout, 429/503, expired token dan reauth.
- Key versi baru invalid, PKS1 lama atau swapped key, context mismatch.
- Resume sesudah pod restart / database failover.
- Kemampuan membaca backup historis setelah retirement.
- Pengukuran throughput, latensi p95/p99, CPU, RSS, OpenBao requests/s,
  database TPS dan storage audit.
