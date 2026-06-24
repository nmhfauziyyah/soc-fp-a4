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

#### A. Diagram Aliran Data (Mermaid Rendered Diagram)
*GitHub akan otomatis merender kode di bawah ini menjadi diagram visual interaktif:*

```mermaid
graph TD
    %% Node Definitions
    subgraph Azure_Cloud [Azure Cloud Infrastructure - Southeast Asia Resource Group: FP SOC]
        subgraph Attack_Simulation [Simulasi Aktivitas]
            Attacker["💻 Agent-2 (Attacker)<br>IP: 172.188.96.13"]
            Victim["🛡️ Agent-1 (Victim/Target)<br>IP: 4.145.88.196"]
        end

        subgraph Central_Defense [Pusat Monitoring & Analisis]
            Manager["🖥️ Wazuh-Manager Server<br>Public IP: 172.188.65.81<br>Private IP: 10.0.0.4"]
            
            subgraph Active_Response_Directory [/var/ossec/active-response/bin/]
                AI_Script["🐍 predict.py (Script Inferensi)"]
                AI_Model["🤖 ddos_model_v2.pkl"]
                AI_Meta["📄 model_metadata_v2.json"]
            end
        end

        subgraph Orchestration [Respons & Otomasi]
            SOAR["⚡ SOAR SHUFFLE<br>(Automated Playbooks)"]
        end
    end

    %% Connection & Data Flow Links
    Attacker -- "Simulasi Serangan<br>(DDoS / Malware / SocEng)" --> Victim
    Victim -- "Kirim Log Aktivitas<br>(Encrypted - Port 1514 TCP)" --> Manager
    
    Manager -- "Trigger Custom Ruleset<br>(ID: 100100, 100101)" --> AI_Script
    AI_Script --- AI_Model
    AI_Script --- AI_Meta
    
    AI_Script -- "Validasi Status Alert<br>(Filter False Positive)" --> SOAR
    SOAR -- "Eksekusi Aksi Blokir / Mitigasi" --> Victim

    %% Styling
    style Azure_Cloud fill:#f9f9f9,stroke:#007fff,stroke-width:2px;
    style Attack_Simulation fill:#fff5f5,stroke:#ff4d4d,stroke-width:1px;
    style Central_Defense fill:#f5faff,stroke:#1890ff,stroke-width:1px;
    style Active_Response_Directory fill:#e6f7ff,stroke:#91d5ff,stroke-width:1px;
    style Orchestration fill:#f6ffed,stroke:#52c41a,stroke-width:1px;
    style Attacker fill:#fff1f0,stroke:#ffa39e;
    style Victim fill:#e6f7ff,stroke:#91d5ff;
    style Manager fill:#efdbff,stroke:#b37feb;


