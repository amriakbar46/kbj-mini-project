# Docker Workflow — Network Traffic Analysis

## 1. Masuk ke Folder Project

```bash
cd "/home/yoan/Yoan/kuliah/ITS/komputasi-berbasis-jaringan/mini-project-lagi/network-analysis"
```

---

# 2. Jalankan Container (START)

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

## Penjelasan
- `-it` → interactive terminal
- `--rm` → container otomatis dihapus saat exit
- `-v` → share folder project host ke container
- `netforensics` → nama Docker image

---

# 3. Test Environment di Dalam Container

```bash
python -c "import pyshark, pandas, scapy; print('container ready')"
```

---

# 4. Keluar dari Container (STOP)

```bash
exit
```

atau:

```text
Ctrl + D
```

---

# 5. Cek Docker Image

```bash
docker images
```

Cari image:

```text
netforensics
```

---

# 6. Cek Container yang Sedang Jalan

```bash
docker ps
```

---

# 7. Cek Semua Container

```bash
docker ps -a
```

---

# 8. Bersihkan Container Mati

```bash
docker container prune
```

---

# 9. Hapus Docker Image

```bash
docker rmi netforensics
```

---

# 10. Rebuild Docker Image

Jika ada perubahan pada:
- Dockerfile
- requirements.txt

jalankan:

```bash
cd docker

sudo docker build -t netforensics .
```

---

# Struktur Project

```text
network-analysis/
├── docker/
│   ├── Dockerfile
│   └── requirements.txt
├── pcap/
├── scripts/
├── output/
├── notebooks/
└── reports/
```

---

# Workflow Penggunaan

## Manual Packet Analysis
Jalankan di host Ubuntu:

```bash
wireshark
```

---

## Python / Automation Analysis
Jalankan container:

```bash
sudo docker run -it --rm \
  -v "$(pwd)":/app \
  netforensics
```

---

# Konsep Penting

## Docker Image
Template environment.

Contoh:
```text
netforensics
```

---

## Docker Container
Instance yang sedang berjalan dari image.

Container bersifat sementara dan akan dihapus otomatis jika menggunakan:
```text
--rm
```

---

# Kenapa Menggunakan `--rm`

Agar container tidak menumpuk setelah selesai digunakan.

Workflow:
```text
run container
↓
analisis
↓
exit
↓
container otomatis dihapus
```

File project tetap aman karena folder host di-mount menggunakan:
```text
-v "$(pwd)":/app
```

---

# Arsitektur Environment

```text
Ubuntu Host
├── Wireshark GUI
├── tshark
└── Docker Engine
        │
        └── netforensics container
            ├── Python
            ├── pyshark
            ├── pandas
            ├── matplotlib
            └── analysis scripts
```
