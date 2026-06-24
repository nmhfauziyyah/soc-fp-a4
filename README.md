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
