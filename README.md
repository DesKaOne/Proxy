# Proxy

Daftar proxy HTTP, HTTPS (HTTP CONNECT), SOCKS4, dan SOCKS5 yang lolos pemeriksaan koneksi saat pembaruan terakhir.

Gunakan Python 3.10+ dan Git. Instal dependensi, termasuk dukungan SOCKS:

```powershell
python -m pip install -r requirements.txt
python main.py
```

`main.py` mengambil kandidat dari Fineproxy dan Triumpactum, menghapus duplikat, lalu memeriksa semuanya secara paralel. Proxy harus mengembalikan respons `204` dari endpoint pemeriksaan Google; redirect tidak diterima. Proxy HTTPS diperiksa melalui HTTPS CONNECT dengan verifikasi sertifikat aktif.

Setelah pemeriksaan selesai, `http.txt`, `https.txt`, `socks4.txt`, dan `socks5.txt` diganti dengan hasil terbaru, kemudian otomatis di-commit dan di-push ke upstream branch saat ini. Hanya empat file hasil yang masuk commit otomatis. Jika hasil sama, tidak dibuat commit kosong, tetapi push tetap dicoba agar commit dari push sebelumnya yang gagal dapat terkirim.

Git harus sudah memiliki identitas commit, akses push, dan upstream. Jika belum ada upstream, atur sekali dengan `git push -u origin main` (sesuaikan nama branch). Kegagalan push ditampilkan sebagai error; hasil dan commit lokal tetap tersedia. Script tidak menjalankan force push atau penggabungan otomatis.

Opsi:

```powershell
python main.py --workers 100 --timeout 10
python main.py --no-push
python -m unittest discover -v
```

`--no-push` tetap memperbarui file hasil lokal. Jika sumber gagal, pemeriksaan dihentikan, atau tidak ada satu pun proxy hidup, hasil lama dipertahankan. Ketersediaan proxy dapat berubah setelah pemeriksaan.

Hanya satu proses pemeriksaan dapat berjalan pada satu repo. Kegagalan mengganti salah satu file hasil memicu pemulihan file yang sudah diganti.

Kode Python tetap lokal sesuai aturan `*.py` pada `.gitignore` repo ini. Semua fungsi dari `proxy.py` sudah digabungkan ke `main.py`.
