# FP SOC

## Anggota Kelompok

| No | Nama Anggota | NRP |
| :-: | :--- | :-: |
| 1 | Ahmad Wildan Fawwaz | 5027241001 |
| 2 | Muhammad Rakha Hananditya Rauf | 5027241015 |
| 3 | Ahmad Yazid Arifuddin | 5027241040 |
| 4 | Muhammad Afrizan Rasya | 5027241048 |
| 5 | Reza Aziz Simatupang | 5027241051 |
| 6 | Dina Rahmadani | 5027241065 |
| 7 | Ni'mah Fauziyyah Atok | 5027241103 |

## 📌 Daftar Isi
1. [Bab 1: Latar Belakang & Permasalahan](#1-latar-belakang--permasalahan)
2. [Bab 2: Arsitektur Jaringan & Sistem](#2-arsitektur-jaringan--sistem)
3. [Bab 3: Alur Fungsi SOC & Tingkat Otonomi AI](#3-alur-fungsi-soc--tingkat-otonomi-ai)
4. [Bab 4: Skenario Simulasi Serangan](#4-skenario-simulasi-serangan)
5. [Bab 5: Analisis Kriteria False Alarms](#5-analisis-kriteria-false-alarms)
6. [Bab 6: Pengembangan & Integrasi Model AI](#6-pengembangan--integrasi-model-ai)
7. [Bab 7: Implementasi SOAR & Respons Serangan](#7-implementasi-soar--respons-serangan)
8. [Bab 8: Metrik Pengujian & Hasil Analisis](#8-metrik-pengujian--hasil-analisis)
9. [Bab 9: Panduan Instalasi & Penggunaan](#9-panduan-instalasi--penggunaan)

---

## 1. Latar Belakang & Permasalahan

### 1.1 Tingginya Angka False Positives di SOC
Pada operasional *Security Operations Center* (SOC) konvensional, tingginya angka alarm palsu (*false positives*) menjadi salah satu tantangan terbesar yang dihadapi oleh tim analis keamanan. Banyaknya peringatan yang tidak valid ini sebagian besar didorong oleh penerapan filosofi **"Better Safe Than Sorry"**. Filosofi ini sengaja memprioritaskan tingkat pengenalan ancaman (*recall*) yang sangat tinggi untuk memastikan tidak ada satu pun serangan nyata yang lolos dari deteksi sistem. 

Namun, efek samping dari peningkatan sensitivitas sistem yang ekstrem ini adalah melonjaknya jumlah *alerts* atau peringatan keamanan harian. Sebagian besar dari peringatan tersebut setelah diperiksa ternyata hanyalah aktivitas jaringan atau sistem yang bersifat aman dan normal (*benign activity*).

### 1.2 Dampak Alert Fatigue dan Kompleksitas Ancaman
Kondisi di atas memicu munculnya beberapa permasalahan kritis di dalam ekosistem kerja SOC:
*   **Alert Fatigue (Kelelahan Mental):** Analis SOC dibanjiri oleh ribuan alarm setiap harinya. Beban kerja yang repetitif untuk menyaring *false positives* ini memicu kejenuhan (*burnout*), yang pada akhirnya justru menurunkan tingkat kewaspadaan analis terhadap ancaman siber yang sesungguhnya.
*   **Ancaman Siber yang Dinamis:** Karakteristik dari ancaman siber modern saat ini berkembang dengan sangat cepat dan dinamis. Hal ini membuat proses pemisahan manual antara aktivitas yang aman dan aktivitas berbahaya yang dilakukan oleh tenaga manusia menjadi semakin sulit, memakan waktu lama, serta rentan terhadap kesalahan (*human error*).

### 1.3 Solusi: Model Kolaborasi Human-AI
Untuk mengatasi keterbatasan tersebut, proyek ini bertujuan mengembangkan sistem SOC yang menerapkan **Model Kolaborasi Human-AI**. Melalui pendekatan ini, kapabilitas pemrosesan data berskala besar (*Large Scale Data Processing*) dan pengambilan keputusan prediktif milik kecerdasan buatan (AI) dipadukan dengan pemahaman kontekstual dan bisnis (*Contextual & Business Knowledge*) yang dimiliki oleh analis manusia. 

Sistem kolaboratif ini dirancang khusus untuk mampu **mereduksi *false alarms* secara signifikan**, meningkatkan efisiensi operasional tiang-tiang pertahanan SOC (Tier 1 hingga Tier 4), tanpa mengorbankan tingkat akurasi deteksi ancaman kritis yang masuk ke dalam sistem.

## 2. Arsitektur Jaringan & Sistem

### 2.1 Infrastruktur Cloud (Azure Deployment)
Arsitektur penanganan insiden dan monitoring keamanan ini dibangun seutuhnya di atas infrastruktur server cloud **Azure for Students** dengan alokasi wilayah (*Location*) di **Southeast Asia** di dalam satu *Resource Group* bernama **FP SOC**[cite: 2]. Infrastruktur ini menyediakan isolasi jaringan serta skalabilitas performa untuk menjalankan *Security Operations Center* (SOC) berbasis kecerdasan buatan.

Seluruh komponen sistem dikerahkan ke dalam 3 instans *Virtual Machine* (VM) Linux dengan rincian spesifikasi operasional sebagai berikut[cite: 2]:

| VM Name | Peran Sistem (Role) | Ukuran VM (Size) | Alamat IP Publik (Public IP) | Alamat IP Privat (Private IP) |
| :--- | :--- | :--- | :--- | :--- |
| **Wazuh-Manager** | Server Pusat Monitoring, Pengolah Alert, & Engine AI | Standard D2s v3 | `172.188.65.81` | `10.0.0.4` |
| **Agent-1** | Target Host / Host Korban (Victim) | Standard B2als | `4.145.88.196` | *(Ditetapkan oleh DHCP Azure)* |
| **Agent-2** | Mesin Simulasi Penyerang (Attacker) | Standard B2als | `172.188.96.13` | *(Ditetapkan oleh DHCP Azure)* |

### 2.2 Konfigurasi Aturan Keamanan Jaringan (Inbound Security Rules)
Untuk memastikan kelancaran aliran data log, registrasi agen secara otomatis, komunikasi dashboard, serta integrasi dengan platform SOAR, konfigurasi *Network Security Group* (NSG) pada sisi **Wazuh-Manager** dibuka dengan aturan masuk (*Inbound*) berikut[cite: 2]:

1. **Port 22 (TCP) - SSH:** 
   Diaktifkan (`Allow`) untuk kebutuhan manajemen jarak jauh, administrasi server, serta pemindahan berkas model AI melalui protokol enkripsi aman[cite: 2].
2. **Port 80 (TCP) - HTTP & Port 443 (TCP) - HTTPS:** 
   Dibuka untuk menyediakan akses enkripsi ke antarmuka grafis Web UI Wazuh Dashboard sehingga analis dapat memantau visualisasi grafik keamanan[cite: 2].
3. **Port 1515 (Any) - allow-agent-1515:** 
   Jalur komunikasi khusus yang digunakan untuk melakukan registrasi otomatis dan autentikasi ketika ada Wazuh Agent baru yang ingin bergabung ke dalam sistem[cite: 2].
4. **Port 1514 (Any) - allow-agent-1514:** 
   Jalur krusial yang berfungsi menerima kiriman data log mentah, data aktivitas sistem, dan indikasi peringatan keamanan dari seluruh agen terpasang secara *real-time*[cite: 2].
5. **Port 9200 (Any) - allow-indexer:** 
   Disediakan khusus untuk interaksi pembacaan dan penulisan basis data log pada modul Wazuh Indexer[cite: 2].
6. **Port 55000 (Any) - allow-wazuh-api:** 
   Jalur API Restful Wazuh yang digunakan untuk integrasi platform otomasi eksternal, seperti SOAR Shuffle, guna membaca alert atau mengeksekusi aksi penanganan insiden[cite: 2].

### 2.3 Komponen Integrasi Sistem SOC
Ekosistem SOC pada proyek ini saling terhubung membentuk satu kesatuan alur kerja arsitektur pertahanan siber modern yang terdiri dari[cite: 1, 2]:
*   **Wazuh Agents (Endpoint Monitoring):** Dipasang pada target host untuk menangkap log aktivitas sistem riil di lapangan (seperti log web server, otentikasi, syslog)[cite: 1, 2].
*   **Wazuh Manager (Central Processor):** Menerima pengiriman log dari agen, mencocokkannya dengan baris aturan (*ruleset*), dan memicu tanda bahaya (*alert*) jika mendeteksi anomali serangan[cite: 1, 2].
*   **Independent AI Module (False Alarm Filter):** Komponen skrip Python inferensi (`predict.py`) beserta model terlatih (`ddos_model_v2.pkl`) yang disisipkan tepat di dalam direktori *Active-Response* milik Wazuh Manager untuk bertindak sebagai penyaring cerdas guna mengeliminasi alarm palsu (*false positives*)[cite: 1, 2].
*   **SOAR Shuffle Platform (Automated Response):** Komponen orkestrasi yang menerima keputusan dari filter keamanan untuk mengeksekusi perintah automasi (*playbooks*) penanganan insiden secara cepat, membuktikan efektivitas ketahanan arsitektur terhadap serangan[cite: 1, 2].

### 2.4 Topologi & Diagram Aliran Data Arsitektur

```text
==========================================================================================
                     AZURE CLOUD INFRASTRUCTURE (Southeast Asia)
                                Resource Group: FP SOC
==========================================================================================

      [ SIMULASI AKTIVITAS ]
      +-----------------------+                         +-----------------------+
      |   Agent-2 (Attacker)  |                         |    Agent-1 (Victim)   |
      |   IP: 172.188.96.13   | --(Simulasi Serangan)-->|    IP: 4.145.88.196   |
      +-----------------------+                         +-----------------------+
                                                                    |
                                                                    | (Kirim Log Jalur
                                                                    |  Port 1514 Encrypted)
                                                                    v
      [ PUSAT MONITORING & ANALISIS ]
      +-------------------------------------------------------------------------+
      | WAZUH-MANAGER SERVER (IP Public: 172.188.65.81 | IP Private: 10.0.0.4)   |
      |                                                                         |
      |  --> Memicu Aturan Kustom (Custom Ruleset ID: 100100, 100101)            |
      |                                                                         |
      |    +---------------------------------------------------------------+    |
      |    | Direktori Active-Response (/var/ossec/active-response/bin/)   |    |
      |    |                                                               |    |
      |    |  [🐍 predict.py] <--> [🤖 ddos_model_v2.pkl]                  |    |
      |    |         |         <--> [📄 model_metadata_v2.json]             |    |
      |    +---------+-----------------------------------------------------+    |
      |              |                                                          |
      |              v (Lolos Filter AI / Validasi Bukan False Positive)        |
      +--------------+----------------------------------------------------------+
                     |
                     v
      [ RESPONS & OTOMASI ]
      +-----------------------+
      |     SOAR SHUFFLE      | --(Eksekusi Aksi Mitigasi / Blokir Aturan)--> [ Selesai ]
      |  (Automated Playbook) |
      +-----------------------+

==========================================================================================
```

## 3. Alur Fungsi SOC & Tingkat Otonomi AI

### 3.1 Pembagian Peran dalam Fungsi SOC (SOC Functions & Roles)
[cite_start]Ekosistem operasional SOC dalam proyek ini dibagi ke dalam 4 tingkatan (*Tiers*) fungsional yang mengintegrasikan kapabilitas sistem otomatisasi dan validasi analis manusia:

* [cite_start]**Tier 1: System Security** Fokus pada manajemen dasar keamanan, yang meliputi konfigurasi sistem (*System configurations*), pengerasan keamanan server (*System Hardening*), serta perlindungan pada titik akhir atau perangkat *client* (*Endpoints Protection*).
* [cite_start]**Tier 1 & 2: Alerts Management** Tahap krusial tempat log mentah diproses melalui korelasi peringatan (*Alerts Correlation*), penentuan skala prioritas ancaman (*Prioritization*), pemilahan *alert* (*Triage*), serta proses validasi untuk memisahkan ancaman nyata dari alarm palsu (*Validation*).
* [cite_start]**Tier 2 & 3: Threat Management** Berfokus pada deteksi aktivitas mencurigakan (*Detection*), investigasi mendalam terhadap indikasi serangan (*Investigation*), analisis akar penyebab masalah (*Root Cause Analysis*), serta tindakan mitigasi awal (*Mitigation*).
* [cite_start]**Tier 3 & 4: Response & Recovery** Tahap eksekusi respons cepat menggunakan skenario otomatisasi (*Playbooks*), pembersihan komprehensif terhadap ancaman (*Threats Eradication*), perubahan kebijakan mitigasi (*Mitigation Changes*), guna menjaga kelangsungan operasional sistem (*Business Continuity*).

### 3.2 Model Kolaborasi Human-AI (Humans in the Loop)
[cite_start]Sistem ini mengimplementasikan siklus kolaborasi timbal balik (*Feedback & Actions Loop*) yang menggabungkan keunggulan dari dua entitas:

1.  **AI Capabilities (Kecerdasan Buatan):**
    * [cite_start]**Large Scale Data Processing:** Mampu mengolah data log mentah berskala besar dari Wazuh Agent dalam hitungan milidetik.
    * [cite_start]**Autonomous Decision Making:** Membuat keputusan mandiri yang cepat untuk memfilter atau mengabaikan log yang dinilai aman.
    * [cite_start]**Predictive Decision Analytics:** Menggunakan model machine learning (`predict.py`) untuk memprediksi probabilitas keabsahan suatu serangan secara akurat[cite: 1, 106].
2.  **Human Capabilities (Analis Manusia):**
    * [cite_start]**Contextual Knowledge:** Memahami konteks insiden yang tidak terbaca oleh algoritma kaku.
    * [cite_start]**System & Business Understanding:** Memahami karakteristik sistem internal dan dampaknya terhadap proses bisnis organisasi.
    * [cite_start]**Strategic Decision Making Capability:** Memiliki wewenang penuh dalam pengambilan keputusan strategis tingkat tinggi saat terjadi insiden kritis.

### 3.3 Tingkat Otonomi AI yang Diimplementasikan
[cite_start]Dalam proyek ini, tingkat otonomi kecerdasan buatan dikonfigurasikan pada **Level 2 (Semi-Autonomous Operation)** menuju **Level 3 (Conditionally Autonomous Operations)**:

* [cite_start]**Mekanisme Kerja:** Modul AI independen kelompok kami (`predict.py`) bertindak sebagai filter otomatis di dalam *pipeline* `active-response` Wazuh[cite: 1, 106, 110]. [cite_start]AI secara mandiri memproses dan memvalidasi setiap alert DDoS yang dipicu oleh aturan kustom (ID: 100100, 100101)[cite: 1, 138].
* [cite_start]**Interaksi Manusia:** Jika model AI mendeteksi adanya indikasi *False Positive* (alarm palsu), AI akan menurunkan prioritas atau mengeliminasi *alert* tersebut secara otomatis demi mencegah terjadinya *alert fatigue* pada analis[cite: 1, 4]. [cite_start]Sebaliknya, jika alert divalidasi sebagai serangan nyata (*True Positive*), data diteruskan ke platform SOAR Shuffle untuk dieksekusi mitigasinya, sementara analis manusia (Human-on-the-Loop) memegang kendali penuh untuk memantau, memberikan umpan balik (*feedback*), atau membatalkan aksi otomatis jika diperlukan.

## 4. Skenario Simulasi Serangan

Berdasarkan spesifikasi seleksi kasus bebas (*free case selection*) pada proyek ini, arsitektur SOC kelompok kami diuji menggunakan 3 skenario simulasi serangan siber berikut[cite: 1]:

### 4.1 Skenario 1: Distributed Denial of Service (DDoS) Attack
*   **Tujuan:** Melakukan uji ketahanan infrastruktur server dengan membanjiri trafik data secara masif untuk melumpuhkan layanan web pada target host.
*   **Mekanisme Simulasi:** 
    *   **Agent-2 (Attacker)** dengan IP `172.188.96.13` bertindak sebagai mesin penyerang yang mengeksekusi *tooling* pengirim paket massal (seperti `hping3` atau `LOIC`) ke arah port HTTP/HTTPS milik **Agent-1 (Victim)**[cite: 2].
    *   Serangan difokuskan pada manipulasi banjir paket (SYN Flood / HTTP Flood) untuk menghabiskan sumber daya komputasi dari target server[cite: 2].
*   **Target Monitoring:** Deteksi lonjakan drastis jumlah koneksi per detik serta kemunculan kode respons error (HTTP 5xx) pada log web server yang direkam oleh Wazuh Agent[cite: 2].

### 4.2 Skenario 2: Malware Deployment & Execution
*   **Tujuan:** Mendeteksi adanya aktivitas penyusupan, pengunduhan, serta eksekusi berkas berbahaya (*malicious payload*) di dalam sistem target.
*   **Mekanisme Simulasi:** 
    *   Penyerang mensimulasikan infeksi *malware* (seperti *reverse shell*, *trojan*, atau skrip berbahaya) ke dalam direktori publik server **Agent-1 (Victim)**[cite: 2].
    *   *Malware* dieksekusi untuk mencoba memanipulasi berkas sistem, menambahkan pengguna tidak sah, atau membuka koneksi keluar secara ilegal (*outbound connection*).
*   **Target Monitoring:** Memanfaatkan fitur *File Integrity Monitoring* (FIM) dan pemantauan proses (*rootcheck*) milik Wazuh Agent untuk menangkap perubahan *hash* berkas penting serta kemunculan proses mencurigakan[cite: 1, 2].

### 4.3 Skenario 3: Social Engineering & Credential Harvesting
*   **Tujuan:** Mensimulasikan dampak dari kelalaian pengguna akibat serangan rekayasa sosial yang berujung pada kebocoran hak akses kredensial administrasi.
*   **Mekanisme Simulasi:** 
    *   Skenario ini diasumsikan melalui keberhasilan penyerang mendapatkan data akun SSH target (`azureuser`) via metode eksternal, yang dilanjutkan dengan aktivitas percobaan masuk berulang kali secara ilegal (*Brute Force Attack*) atau akses masuk tidak wajar pada jam kerja yang tidak biasa[cite: 2].
*   **Target Monitoring:** Analisis log otentikasi sistem (`/var/log/auth.log` atau `secure`) pada **Agent-1** untuk menangkap pola *Failed SSH Logins* dalam frekuensi tinggi sebelum terjadinya *Successful Login* yang tidak sah[cite: 2].

---

## 5. Analisis Kriteria False Alarms

Untuk memisahkan antara ancaman valid (*True Positive*) dan alarm palsu (*False Positive*), kelompok kami mendefinisikan kriteria klasifikasi secara mandiri berdasarkan karakteristik data log mentah yang dikumpulkan oleh Wazuh Manager[cite: 1]:

### 5.1 Kriteria Deteksi pada Log Mentah Wazuh
Wazuh Manager menangkap parameter-parameter dasar dari setiap aktivitas jaringan yang dikirimkan oleh agen, antara lain: `src_ip` (IP asal), `dst_port` (port tujuan), `data.protocol` (protokol data), `firedtimes` (frekuensi pemicu), dan status otentikasi.

### 5.2 Matriks Perbedaan True Positive vs False Positive
Sistem kolaborasi AI kami dilatih menggunakan berkas kustom metadata untuk mengenali ambang batas kriteria berikut[cite: 2]:

| Kategori Kasus | Kriteria True Positive (Ancaman Nyata) | Kriteria False Positive (Alarm Palsu / Trafik Normal) |
| :--- | :--- | :--- |
| **Simulasi DDoS** | Terdapat pengiriman paket dari IP luar secara terus-menerus (>100 *requests* per detik) pada port 80/443, memicu aturan kustom ID `100100` atau `100101`[cite: 2]. | Lonjakan trafik tinggi yang berasal dari aktivitas pemindaian internal yang sah, proses *backup data* terjadwal, atau lonjakan kunjungan pengguna asli (*flash crowd*). |
| **Simulasi Malware** | Terjadinya modifikasi berkas pada direktori sistem inti (`/etc`, `/bin`) yang dibarengi dengan munculnya proses asing dengan hak akses *root*[cite: 1]. | Proses pembaruan perangkat lunak resmi sistem (*system auto-update*) atau modifikasi konfigurasi yang dilakukan oleh administrator resmi (`azureuser`)[cite: 2]. |
| **Social Engineering** | Kegagalan login SSH berturut-turut dalam waktu singkat diikuti oleh login sukses dari alamat IP publik asing yang tidak dikenal[cite: 2]. | Analis atau administrator resmi salah memasukkan kata sandi sebanyak 2-3 kali sebelum akhirnya berhasil masuk menggunakan IP yang terdaftar[cite: 2]. |

## 6. Pengembangan & Integrasi Model AI

### 6.1 Deskripsi Komponen AI Mandiri
Sesuai dengan spesifikasi tugas yang melarang penggunaan API pihak ketiga, kelompok kami mengembangkan model kecerdasan buatan berbasis *Machine Learning* secara mandiri menggunakan modul Python (`model-ddos-wazuhv3.ipynb`). Model ini dilatih untuk menganalisis karakteristik log secara kontekstual guna membedakan antara serangan DDoS nyata (*True Positive*) dan lonjakan trafik normal (*False Positive*).

Komponen AI hasil kompilasi dari notebook ini melahirkan tiga berkas utama yang ditempatkan pada direktori `/var/ossec/active-response/bin/` di server Wazuh Manager:
1.  `ddos_model_v2.pkl`: Berkas biner model ML terlatih yang menyimpan bobot keputusan klasifikasi.
2.  `model_metadata_v2.json`: Berkas konfigurasi yang memuat daftar fitur (*features extraction*) hasil prapemrosesan log mentah Wazuh (seperti volume alert, frekuensi `firedtimes`, dan pola IP).
3.  `predict.py`: Skrip inferensi utama berbasis Python 3 yang melakukan pembacaan log dari *stdin*, memuat model `.pkl`, mengekstrak fitur sesuai `.json`, dan menghasilkan keputusan filter.

### 6.2 Alur Pemrosesan Data & Fitur Model AI
Model AI di dalam repositori ini bekerja dengan mengekstrak beberapa fitur penting dari data JSON alert Wazuh secara berkala (*buffering window*):
* **Alert Volume Timeline:** Menghitung total pemicu alert dalam rentang waktu tertentu untuk mendeteksi anomali volume paket masif.
* **Label Distribution & Feature Importance:** Model mengevaluasi bobot kecurigaan berdasarkan ID aturan kustom, protokol jaringan yang digunakan, serta keunikan alamat IP asal (`src_ip`).

### 6.3 Otomasi Pemasangan Modul AI (Single Bash Script)
Untuk menyederhanakan proses pemasangan, seluruh tahapan deployment berkas, instalasi *dependency library* pada framework Python internal Wazuh, pemformatan izin akses, hingga injeksi baris konfigurasi ke `/var/ossec/etc/ossec.conf` dapat dieksekusi melalui satu perintah Bash berikut:

```bash
#!/bin/bash

# ==============================================================================
# SCRIPT DEPLOYMENT & INTEGRASI MODUL AI - FP SOC
# Jalankan script ini langsung di dalam server Wazuh Manager
# ==============================================================================

echo "===================================================="
echo "[+] Memindahkan file model AI ke folder Active-Response..."
sudo mv /tmp/ddos_model_v2.pkl /var/ossec/active-response/bin/
sudo mv /tmp/predict.py /var/ossec/active-response/bin/
sudo mv /tmp/model_metadata_v2.json /var/ossec/active-response/bin/

echo "[+] Mengonfigurasi hak akses aman dan kepemilikan berkas..."
sudo chmod 750 /var/ossec/active-response/bin/predict.py
sudo chown root:wazuh /var/ossec/active-response/bin/predict.py

echo -e "\n[+] Menginstall library python ke framework internal terisolasi Wazuh..."
sudo /var/ossec/framework/python/bin/pip3 install joblib numpy scikit-learn --break-system-packages

echo -e "\n[+] Menyisipkan konfigurasi Active Response ke /var/ossec/etc/ossec.conf..."
# Membuat backup file ossec.conf demi keamanan
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# Menyisipkan tag <command> dan <active-response> sebelum tag penutup </ossec_config>
sudo sed -i '/<\/ossec_config>/i \
  <command>\n    <name>ddos-ai-predict<\/name>\n    <executable>predict.py<\/executable>\n    <timeout_allowed>yes<\/timeout_allowed>\n  <\/command>\n\n  <active-response>\n    <command>ddos-ai-predict<\/command>\n    <location>local<\/location>\n    <rules_id>100100,100101<\/rules_id>\n  <\/active-response>' /var/ossec/etc/ossec.conf

echo -e "\n[+] Menerapkan konfigurasi baru dengan restart wazuh-manager..."
sudo systemctl restart wazuh-manager

echo -e "\n[✓] Proses integrasi komponen AI dari Notebook v3 selesai!"
echo "===================================================="
```

## 6. Pengembangan & Integrasi Model AI

### 6.1 Deskripsi Komponen AI Mandiri
Sesuai dengan spesifikasi tugas yang melarang penggunaan API pihak ketiga, kelompok kami mengembangkan model kecerdasan buatan berbasis *Machine Learning* secara mandiri menggunakan modul Python (`model-ddos-wazuhv3.ipynb`). Model ini dilatih untuk menganalisis karakteristik log secara kontekstual guna membedakan antara serangan DDoS nyata (*True Positive*) dan lonjakan trafik normal (*False Positive*).

Komponen AI hasil kompilasi dari notebook ini melahirkan tiga berkas utama yang ditempatkan pada direktori `/var/ossec/active-response/bin/` di server Wazuh Manager:
1.  `ddos_model_v2.pkl`: Berkas biner model ML terlatih yang menyimpan bobot keputusan klasifikasi.
2.  `model_metadata_v2.json`: Berkas konfigurasi yang memuat daftar fitur (*features extraction*) hasil prapemrosesan log mentah Wazuh (seperti volume alert, frekuensi `firedtimes`, dan pola IP).
3.  `predict.py`: Skrip inferensi utama berbasis Python 3 yang melakukan pembacaan log dari *stdin*, memuat model `.pkl`, mengekstrak fitur sesuai `.json`, dan menghasilkan keputusan filter.

### 6.2 Alur Pemrosesan Data & Fitur Model AI
Model AI di dalam repositori ini bekerja dengan mengekstrak beberapa fitur penting dari data JSON alert Wazuh secara berkala (*buffering window*):
* **Alert Volume Timeline:** Menghitung total pemicu alert dalam rentang waktu tertentu untuk mendeteksi anomali volume paket masif.
* **Label Distribution & Feature Importance:** Model mengevaluasi bobot kecurigaan berdasarkan ID aturan kustom, protokol jaringan yang digunakan, serta keunikan alamat IP asal (`src_ip`).

### 6.3 Otomasi Pemasangan Modul AI (Single Bash Script)
Untuk menyederhanakan proses pemasangan, seluruh tahapan deployment berkas, instalasi *dependency library* pada framework Python internal Wazuh, pemformatan izin akses, hingga injeksi baris konfigurasi ke `/var/ossec/etc/ossec.conf` dapat dieksekusi melalui satu perintah Bash berikut:

```bash
#!/bin/bash

# ==============================================================================
# SCRIPT DEPLOYMENT & INTEGRASI MODUL AI - FP SOC
# Jalankan script ini langsung di dalam server Wazuh Manager
# ==============================================================================

echo "===================================================="
echo "[+] Memindahkan file model AI ke folder Active-Response..."
sudo mv /tmp/ddos_model_v2.pkl /var/ossec/active-response/bin/
sudo mv /tmp/predict.py /var/ossec/active-response/bin/
sudo mv /tmp/model_metadata_v2.json /var/ossec/active-response/bin/

echo "[+] Mengonfigurasi hak akses aman dan kepemilikan berkas..."
sudo chmod 750 /var/ossec/active-response/bin/predict.py
sudo chown root:wazuh /var/ossec/active-response/bin/predict.py

echo -e "\n[+] Menginstall library python ke framework internal terisolasi Wazuh..."
sudo /var/ossec/framework/python/bin/pip3 install joblib numpy scikit-learn --break-system-packages

echo -e "\n[+] Menyisipkan konfigurasi Active Response ke /var/ossec/etc/ossec.conf..."
# Membuat backup file ossec.conf demi keamanan
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

# Menyisipkan tag <command> dan <active-response> sebelum tag penutup </ossec_config>
sudo sed -i '/<\/ossec_config>/i \
  <command>\n    <name>ddos-ai-predict<\/name>\n    <executable>predict.py<\/executable>\n    <timeout_allowed>yes<\/timeout_allowed>\n  <\/command>\n\n  <active-response>\n    <command>ddos-ai-predict<\/command>\n    <location>local<\/location>\n    <rules_id>100100,100101<\/rules_id>\n  <\/active-response>' /var/ossec/etc/ossec.conf

echo -e "\n[+] Menerapkan konfigurasi baru dengan restart wazuh-manager..."
sudo systemctl restart wazuh-manager

echo -e "\n[✓] Proses integrasi komponen AI dari Notebook v3 selesai!"
echo "===================================================="
```

## 8. Metrik Pengujian & Hasil Analisis (Benchmark)

### 8.1 Metrik Pengukuran Performa
Berdasarkan keluaran pengujian dari berkas Jupyter Notebook `model-ddos-wazuhv3.ipynb`, performa arsitektur SOC kelompok kami diukur menggunakan matriks evaluasi standar pertahanan keamanan siber berikut:
* **False Alarm Reduction Rate (FARR):** Rasio persentase tingkat keberhasilan model AI dalam mereduksi dan menyaring alarm palsu (*false positives*).
* **Detection Accuracy & Recall:** Pengukuran kestabilan model untuk menjamin bahwa penyaringan alarm palsu tidak mengorbankan sensitivitas sistem terhadap serangan DDoS asli (*True Positive*).
* **Mean Time to Respond (MTTR):** Durasi total waktu respons yang dibutuhkan sejak Agent-2 menginisiasi serangan siber hingga SOAR Shuffle berhasil mengisolasi atau memblokir penyerang pada sisi Agent-1.

### 8.2 Hasil Analisis Benchmark (Sebelum vs Sesudah Integrasi AI)
Berdasarkan pengujian model integrasi data, berikut adalah perbandingan metrik operasional sistem SOC kelompok kami:

| Parameter Uji | Sebelum Integrasi AI (Wazuh Standar) | Sesudah Integrasi AI (Human-AI Model) |
| :--- | :---: | :---: |
| **Volume False Alarms / Hari** | Tinggi (*Memicu Alert Fatigue*) | Mereduksi Secara Signifikan |
| **Akurasi Klasifikasi Serangan** | Kaku (Hanya mencocokkan baris Ruleset) | Tinggi & Adaptif (Berbasis *Machine Learning*) |
| **Waktu Eksekusi Blokir Serangan** | Manual oleh Analis (Memakan waktu lama) | Otomatis via SOAR (Selesai dalam hitungan detik) |

### 8.3 Visualisasi Evaluasi Model
Model machine learning yang dikembangkan juga menghasilkan visualisasi metrik evaluasi yang tersimpan di dalam direktori proyek. Gambar-gambar grafik berikut dapat dirujuk untuk analisis performa yang lebih mendalam:
* `alert_volume_timeline.png` (Analisis volume pemicu alert berdasarkan rentang waktu)
* `label_distribution.png` (Distribusi kelas data latih)
* `eval_confusion_roc.png` (Matriks konfusi dan kurva karakteristik operasi penerima untuk akurasi model)
* `feature_importance.png` (Bobot pengaruh fitur log terhadap keputusan klasifikasi AI)

## 9. Panduan Instalasi & Penggunaan

### 9.1 Akses Manajemen & Monitoring Sistem
Untuk memudahkan pengelolaan infrastruktur cloud, klaster Virtual Machine dapat diakses melalui SSH menggunakan detail alamat berikut:
*   **Wazuh Manager Server:** `azureuser@172.188.65.81`
*   **Agent-1 (Victim Host):** `azureuser@4.145.88.196`
*   **Agent-2 (Attacker Host):** `azureuser@172.188.96.13`

Sedangkan untuk memantau visualisasi metrik keamanan dan status alert, Anda dapat mengakses antarmuka grafis web dengan detail berikut:
*   **URL Wazuh Dashboard:** `https://172.188.65.81`
*   **Kredensial Akses:**
    *   **Username:** `admin`
    *   **Password:** `F+PSVLDBqXjAgkHfeCkqXNsk?3vVjE44`

### 9.2 Skrip Otomasi Pemeriksaan Kesehatan Sistem (System Health Check)
Guna memastikan seluruh core engine Wazuh, modul indexer, dashboard web, serta status konektivitas jaringan antar Agent berjalan normal setelah integrasi AI, jalankan skrip Bash serbaguna di bawah ini langsung di server **Wazuh Manager**:

```bash
#!/bin/bash

# ==============================================================================
# SCRIPT UTALITAS SOC - DIAGNOSTIK KESEHATAN SISTEM & KONEKTIVITAS
# Jalankan script ini di server Wazuh Manager untuk validasi pasca-integrasi AI
# ==============================================================================

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_BLUE="\033[0;34m"
COLOR_YELLOW="\033[1;33m"

echo -e "${COLOR_BLUE}======================================================${COLOR_RESET}"
echo -e "${COLOR_BLUE}      SOC SYSTEM HEALTH CHECK & DIAGNOSTIC UTILITY    ${COLOR_RESET}"
echo -e "${COLOR_BLUE}======================================================${COLOR_RESET}"

# 1. Memeriksa Status Layanan Core System
echo -e "\n${COLOR_YELLOW}[1/3] Memeriksa Status Layanan Utama Server Pusat...${COLOR_RESET}"
SERVICES=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")

for SVC in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SVC"; then
        echo -e "  [${COLOR_GREEN}OK${COLOR_RESET}] Layanan ${COLOR_GREEN}$SVC${COLOR_RESET} berjalan dengan normal."
    else
        echo -e "  [${COLOR_RED}FAIL${COLOR_RESET}] Layanan ${COLOR_RED}$SVC${COLOR_RESET} mati atau mengalami error!"
    fi
done

# 2. Memeriksa Port Penting yang Terbuka
echo -e "\n${COLOR_YELLOW}[2/3] Memeriksa Ketersediaan Port Komunikasi Integrasi...${COLOR_RESET}"
PORTS=(1514 1515 55000 9200 443)

for PORT in "${PORTS[@]}"; do
    if ss -tuln | grep -q ":$PORT "; then
        echo -e "  [${COLOR_GREEN}OPEN${COLOR_RESET}] Port ${COLOR_GREEN}$PORT${COLOR_RESET} aktif mendengarkan koneksi."
    else
        echo -e "  [${COLOR_RED}CLOSED${COLOR_RESET}] Port ${COLOR_RED}$PORT${COLOR_RESET} tertutup! Periksa konfigurasi firewall/NSG Azure."
    fi
done

# 3. Memeriksa Status Konektivitas Jaringan Endpoint Agent
echo -e "\n${COLOR_YELLOW}[3/3] Menguji Ping Konektivitas Jaringan Antar Host...${COLOR_RESET}"
AGENTS=("4.145.88.196" "172.188.96.13")
AGENT_NAMES=("Agent-1 (Victim)" "Agent-2 (Attacker)")

for i in "${!AGENTS[@]}"; do
    IP=${AGENTS[$i]}
    NAME=${AGENT_NAMES[$i]}
    
    if ping -c 1 -W 2 "$IP" > /dev/null 2>&1; then
        echo -e "  [${COLOR_GREEN}ONLINE${COLOR_RESET}] Berhasil terhubung ke ${COLOR_GREEN}$NAME ($IP)${COLOR_RESET}."
    else
        echo -e "  [${COLOR_RED}OFFLINE${COLOR_RESET}] Gagal menjangkau ${COLOR_RED}$NAME ($IP)${COLOR_RESET}. Cek rule inbound/outbound."
    fi
done

echo -e "\n${COLOR_BLUE}======================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}[✓] Proses diagnostik kesehatan sistem SOC selesai!${COLOR_RESET}"
echo -e "${COLOR_BLUE}======================================================${COLOR_RESET}"
```
