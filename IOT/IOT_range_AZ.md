# CPENT Live Range - IoT Firmware Analysis Walkthrough & Solution Guide

> **Sənəd Növü:** Senior Penetration Tester & IoT Firmware Security Texniki Hesabatı  
> **Hədəf Mühit:** CPENT IoT Range (172.25.101.0/24)  
> **Suallar:** Challenge 26 - Challenge 61  
> **Tərtib Edən:** Senior Pentester & Security Engineer  

---

## 1. Giriş və IoT Şəbəkə Topologiyası

CPENT IoT laboratoriyası daxili proqram təminatının (Firmware) statik və dinamik analizini, binar başlıqların (BIN-Header, TRX, uImage) tədqiqini, sıxılmış fayl sistemlərinin (Squashfs, JFFS2, LZMA, gzip) aşkarlanmasını və açılmasını (unpacking), şifrələnmiş (XOR-encrypted) firmware paketlərinin bərpasını, daxili konfiqurasiya fayllarında sərt kodlanmış (hardcoded) parolların tapılmasını və IoT rabitə protokollarının (HNAP, SOAP) araşdırılmasını əhatə edir.

### Hədəf Maşınların və Binar Faylların Xəritəsi

| Hədəf IP | Firmware Faylı | Fayl Sistemi / Format | Təhlil Növü / İstismar Vektoru | Əlaqəli Suallar |
| :--- | :--- | :--- | :--- | :--- |
| `172.25.101.100` | `FileOne.bin` | Squashfs (447 inodes), TRX | Başlıq analizi, MIPS32 binar və Pwnable təhlili | Challenge 26 - 38 |
| `172.25.101.100` | `FileTwo.bin` | Squashfs (1119 inodes), uImage | CRC başlığı, entropiya analizi, sıxılma yoxlanışı | Challenge 39 - 43 |
| `172.25.101.100` | `FileThree.bin` | XOR Şifrələnmiş uImage (LZMA) | Entropiya analizi, 8-bayt XOR açarının tapılması və deşifrə | Challenge 44, 45, 61 |
| `172.25.101.200` | `IOT.bin` | Squashfs, TRX, gzip ("piggy") | TRX və gzip başlıq ofsetləri, fayl sistemi aşkarlanması | Challenge 46 - 50 |
| `172.25.101.200` | `IOT2.bin` | JFFS2 (Little Endian), uImage | Çoxsaylı uImage başlıqları, sıxılmış fayl ölçüsü (26 MB) | Challenge 51 - 55 |
| `172.25.101.200` | `IOT3.bin` | Squashfs | Dərin rekursiv açılma, sərt kodlanmış parol (`check_fwmode`) | Challenge 56 - 58 |
| `172.25.101.200` | `IOT4.bin` | Squashfs (LZMA), uImage | `dd` ilə kəsmə, HNAP protokolu və SOAP rabitə ailəsi | Challenge 59 - 60 |

---

## 2. IoT Range Tapşırıqlarının Ətraflı Həlli (Q26 - Q61)

---

### Hissə 1: CTF 1 - FileOne.bin Analizi (`172.25.101.100`)

Bu mərhələdə `cpent@172.25.101.100` maşınına daxil olunur (`cpentpw`), `/home/cpent/firmware/FileOne.bin` faylı tədqiq edilir.

#### Başlıq və Fayl Sistemi Kəşfiyyatı:
```bash
ssh cpent@172.25.101.100
# Parol: cpentpw

cd /home/cpent/firmware/
file FileOne.bin
# FileOne.bin: data

binwalk -t FileOne.bin
# DECIMAL   HEXADECIMAL DESCRIPTION
# 0         0x0         BIN-Header, board ID: 1550, hardware version: 4702, firmware version: 1.0.0, build date: 2012-02-08
# 32        0x20        TRX firmware header, little endian, image size: 7753728 bytes, CRC32: 0x436822F6...
# 60        0x3C        gzip compressed data, maximum compression, has original file name: "piggy"...
# 1648424   0x192728    Squashfs filesystem, little endian, version 3.0, size: 6099215 bytes, 447 inodes...
```

![FileOne Binwalk Başlıq Analizi](./ch26_31_fileone_binwalk_header.png)

---

#### Challenge 26: FileOne.bin Fayl Növü
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the type of the file. (For example, ascii, executable, data)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxx`
* **Hədəf:** `172.25.101.100` (`FileOne.bin`)
* **Metodologiya:**
  `file FileOne.bin` komandası icra edildikdə faylın tipi binar data kimi müəyyən edilir: `FileOne.bin: data`.
* **Düzgün Cavab:** `data`

---

#### Challenge 27: FileOne.bin Firmware Versiyası
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the firmware version of the FileOne.bin image (Answer Format: N.N.N)
* **Bal:** 50 Points
* **Cavab Formatı:** `N.N.N`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `binwalk -t FileOne.bin` çıxışında 0x0 ofsetindəki BIN-Header daxilində `firmware version: 1.0.0` qeyd olunub.
* **Düzgün Cavab:** `1.0.0`

---

#### Challenge 28: FileOne.bin Board ID
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the Board ID in the bin header. (Answer Format: NNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  BIN-Header məlumatlarında lövhə identifikatoru göstərilir: `board ID: 1550`.
* **Düzgün Cavab:** `1550`

---

#### Challenge 29: FileOne.bin Fayl Sistemi Növü
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the type of file system is within the FileOne.bin image. (Answer Format: xxxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Binwalk çıxışında 0x192728 ofsetində `Squashfs filesystem` yerləşdiyi görünür. Format tələbinə uyğun olaraq kiçik hərflərlə `squashfs` yazılır.
* **Düzgün Cavab:** `squashfs`

---

#### Challenge 30: FileOne.bin Firmware Yaradılma Tarixi (Build Date)
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the build date of the firmware of the FileOne.bin image. (Date Format: YYYY-MM-DD)
* **Bal:** 50 Points
* **Cavab Formatı:** `YYYY-MM-DD`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  BIN-Header daxilində `build date: 2012-02-08` qeyd edilmişdir.
* **Düzgün Cavab:** `2012-02-08`

---

#### Challenge 31: FileOne.bin İnode Sayı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the number of inodes in the FileOne.bin firmware image. (Answer Format: NNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNN`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Squashfs bölməsində fayl indeks düyünlərinin (inodes) miqdarı göstərilir: `447 inodes`.
* **Düzgün Cavab:** `447`

---

#### Challenge 32: Web Səhifəsi Faylının Genişlənməsi (Extension)
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the extension of the web page file in the file system of the firmware image. (Answer Format: xxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `binwalk -e FileOne.bin` ilə fayl sistemi çıxarılır və web faylları axtarılır:
  ```bash
  cd _FileOne.bin.extracted/squashfs-root/
  find . -type f \( -name "*.html" -o -name "*.php" -o -name "*.htm" -o -name "*.asp" -o -name "*.cgi" \) 2>/dev/null
  # ./www/index.asp
  ```
  Web faylının genişlənməsi `asp`-dir.
* **Düzgün Cavab:** `asp`
* **Əlaqəli Şəkil:**

![FileOne Web Səhifəsi Genişlənməsi](./ch32_fileone_web_extension_asp.png)

---

#### Challenge 33: /usr/local Kataloqundakı Xidmət
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and identify the service that is listed under the /usr/local folder in the file system of the firmware image. (Answer Format: xxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Çıxarılmış `squashfs-root/usr/local/` qovluğunun məzmunu yoxlanılır:
  ```bash
  ls -la usr/local/
  # samba
  ```
  Xidmət qovluğu `samba`-dır.
* **Düzgün Cavab:** `samba`
* **Əlaqəli Şəkil:**

![FileOne usr/local Samba Xidməti](./ch33_fileone_usr_local_samba.png)

---

#### Challenge 34: Hücum Baxımından Maraq Doğuran Qovluq
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileOne.bin and find the folder that appears to contain items of interest from an attack standpoint. (Answer Format: xxxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `squashfs-root` daxilindəki kataloqlara baxıldıqda birbaşa istismar təlimləri və tapşırıqları saxlayan `pwnable` qovluğu aşkar olunur.
* **Düzgün Cavab:** `pwnable`

---

#### Challenge 35: İstismar Binar Fayllarının CPU Arxitekturası
* **Sual (İmtahan Mətni):** What is the CPU architecture of the exploits provided in the file system? Include the bitness in your answer. (Answer Format: XXXXNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXXXNN`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `pwnable` qovluğundakı binar fayllar `file` komandası ilə yoxlanılır:
  ```bash
  file ShellCode_Required/*
  # socket_bof: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV)...
  ```
  Format tələbinə (`XXXXNN`) əsasən arxitektura `MIPS32`-dir.
* **Düzgün Cavab:** `MIPS32`
* **Əlaqəli Şəkil:**

![FileOne Pwnable və MIPS32 Arxitekturası](./ch34_35_fileone_pwnable_mips32.png)

---

#### Challenge 36: heapoverflow_01 Faylının Stripped Statusu
* **Sual (İmtahan Mətni):** Is the heapoverflow_01 binary stripped? (Answer with "true" or "false")
* **Bal:** 50 Points
* **Cavab Formatı:** `true or false`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `pwnable/Intro/heap_overflow_01` faylı yoxlanılır:
  ```bash
  file heap_overflow_01
  # heap_overflow_01: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV)... not stripped
  ```
  Fayl `not stripped` olduğu üçün cavab `false`-dur.
* **Düzgün Cavab:** `false`
* **Əlaqəli Şəkil:**

![heapoverflow_01 Stripped Təhlili](./ch36_heapoverflow01_not_stripped.png)

---

#### Challenge 37: heapoverflow_01 Program Headers Sayı
* **Sual (İmtahan Mətni):** How many program headers are in the heapoverflow_01 binary? (Answer Format: N)
* **Bal:** 50 Points
* **Cavab Formatı:** `N`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  `readelf -l heap_overflow_01` icra edilir:
  ```bash
  readelf -l heap_overflow_01 | head -n 5
  # There are 6 program headers, starting at offset 52
  ```
* **Düzgün Cavab:** `6`

---

#### Challenge 38: heapoverflow_01 Giriş Nöqtəsi (Entry Point)
* **Sual (İmtahan Mətni):** What is the address of the entry point in the heapoverflow_01 binary? Include the 0x prefix. (Answer Format: 0xNNNNNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `0xNNNNNNN`
* **Hədəf:** `172.25.120.100`
* **Metodologiya:**
  `readelf -l heap_overflow_01` çıxışında giriş nöqtəsi göstərilir: `Entry point 0x400640`.
* **Düzgün Cavab:** `0x400640`
* **Əlaqəli Şəkil:**

![heapoverflow_01 Headers və Entry Point](./ch37_38_heapoverflow01_headers_entry.png)

---

### Hissə 2: CTF 2 - FileTwo.bin Tədqiqatı (`172.25.101.100`)

Bu hədəf `FileTwo.bin` faylının uImage başlığı, CRC yoxlama cəmi və entropiya analizini əhatə edir.

#### Fayl Kəşfiyyatı və Entropiya Yoxlanışı:
```bash
file FileTwo.bin
# FileTwo.bin: data

binwalk -t FileTwo.bin
# 96    0x60    uImage header, header CRC: 0x7FE9E826, compression type: lzma, image name: "Linux Kernel Image"
# 160   0xA0    LZMA compressed data
# 917632 0xE0080 Squashfs filesystem, version 3.0, 1119 inodes...

binwalk -E FileTwo.bin
# 0       0x0      Rising entropy edge (0.982635)
# 878592  0xD6800  Falling entropy edge (0.000000)
# 919552  0xE0800  Rising entropy edge (0.989207)
# 3172352 0x306800 Falling entropy edge (0.784498)
```

![FileTwo Binwalk Başlıq Analizi](./ch39_42_filetwo_binwalk_header.png)
![FileTwo Entropiya Analizi](./ch41_filetwo_entropy_analysis.png)

---

#### Challenge 39: FileTwo.bin Fayl Sistemi
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileTwo.bin and identify the file system within the image. (Answer Format: xxxxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxxx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  0xE0080 ofsetində yerləşən fayl sistemi: `Squashfs filesystem`. Cavab kiçik hərflərlə: `squashfs`.
* **Düzgün Cavab:** `squashfs`

---

#### Challenge 40: FileTwo.bin CRC Dəyərinin Son 4 Hex Rəqəmi
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileTwo.bin and find the last four hexadecimal digits of its CRC. (Answer Format: XNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `XNNN`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  uImage başlığındakı `header CRC: 0x7FE9E826` dəyərinin son dörd simvolu `E826`-dır.
* **Düzgün Cavab:** `E826`

---

#### Challenge 41: FileTwo.bin Şifrələnmə Vəziyyəti
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileTwo.bin and determine if the data in the image is encrypted. (Answer with "True" or "False")
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Entropiya qrafikində kəskin düşmələr (Falling entropy edge 0.000000) və binar daxilində açıq stringlər/Unix yolları mövcuddur. Məlumat şifrələnməyib (`False`).
* **Düzgün Cavab:** `False`

---

#### Challenge 42: FileTwo.bin Sıxılma Vəziyyəti
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileTwo.bin and determine if the data in the image is compressed. (Answer with "True" or "False")
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  0xA0 ofsetində `LZMA compressed data` və uImage başlığında `compression type: lzma` aşkarlanmışdır. Buna görə binar sıxılmışdır (`True`).
* **Düzgün Cavab:** `True`

---

#### Challenge 43: FileTwo.bin Root Parolunun Son 4 Simvolu
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze the file FileTwo.bin and find the last 4 characters of the root password for the FileTwo.bin image. (Answer Format: NNNx)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNx`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Bu firmware təsvirində laboratoriya mühitində fayl sisteminin konfiqurasiya zədələnməsi səbəbilə root parolu düzgün təyin edilə bilməmiş və sual laboratoriya xətası kimi qeydə alınmışdır.
* **Düzgün Cavab:** `[Laboratoriya mühitindəki xəta səbəbilə boş saxlanılıb]`
* **Əlaqəli Şəkil:**

![FileTwo Çıxarılmış etc Qovluğu](./ch39_43_filetwo_extracted_etc.png)

---

### Hissə 3: CTF 3 - FileThree.bin XOR Deşifrə və Sıxılma Təhlili (`172.25.101.100`)

Bu seqmentdə `FileThree.bin` faylı tədqiq edilir. Fayl yüksək entropiyaya malikdir və binarın sonunda təkrarlanan 8-baytlıq XOR açarı vasitəsilə şifrələnmişdir.

#### XOR Şifrəsinin Aşkarlanması və Bərpası:
```bash
binwalk -E FileThree.bin
# Sabit yüksək entropiya (0.979)

hexdump -C FileThree.bin | tail -n 30
# 00340000  88 44 a2 d1 a9 d0 73 7b  88 45 1f d3 f0 bc 5a 2d
# 00340030  96 44 a2 d1 68 b4 5a 2d  88 44 a2 d1 68 b4 5a 2d
# 00340040  88 44 a2 d1 68 b4 5a 2d  88 44 a2 d1 68 b4 5a 2d
# Təkrarlanan XOR açarı: 8844a2d168b45a2d
```

Python skripti ilə deşifrə icra edilir:
```python
key = bytes.fromhex('8844a2d168b45a2d')
data = open('FileThree.bin', 'rb').read()
open('decrypt.bin', 'wb').write(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)))
```

Deşifrə edilmiş fayl yoxlanılır:
```bash
binwalk decrypt.bin
# 128     0x80     uImage header, compression type: lzma, image name: "Linux Kernel Image"
# 192     0xC0     LZMA compressed data
# 1429632 0x15D080 Squashfs filesystem, version 4.0, compression:xz...
```

![FileThree Entropiya və Strings](./ch44_45_filethree_entropy_strings.png)
![FileThree XOR Deşifrə Skripti](./ch45_filethree_xor_decrypt.png)
![FileThree Deşifrə Edilmiş Binwalk](./ch61_filethree_decrypted_binwalk.png)

---

#### Challenge 44: FileThree.bin Sıxılma Vəziyyəti
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileThree.bin and determine if the data in the image is compressed. (Answer with "True" or "False")
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Fayl ilkin vəziyyətdə sıxılmış deyil, XOR şifrələməsi altında saxlanılır və adi arxivatorlar tərəfindən oxuna bilmir. Buna görə cavab `False`-dur.
* **Düzgün Cavab:** `False`

---

#### Challenge 45: FileThree.bin Şifrələnmə Vəziyyəti
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileThree.bin and determine if the data in the image is encrypted. (Answer with "True" or "False")
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Entropiya təhlili və faylın sonundakı `88 44 a2 d1 68 b4 5a 2d` təkrarlanan padding strukturu binarın şifrələndiyini sübut edir (`True`).
* **Düzgün Cavab:** `True`

---

#### Challenge 61: FileThree.bin Sıxılma Tipi
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.100, analyze FileThree.bin and identify the compression type used in the image. (Answer Format: XXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXXX`
* **Hədəf:** `172.25.101.100`
* **Metodologiya:**
  Deşifrə edilmiş `decrypt.bin` faylının uImage başlığı oxunduqda `compression type: lzma` göstərilir. Format tələbinə (`XXXX`) uyğun cavab `LZMA`-dır.
* **Düzgün Cavab:** `LZMA`

---

### Hissə 4: CTF 4 - IOT.bin Başlıq və Fayl Sistemi Tədqiqatı (`172.25.101.200`)

Bu hədəf maşından (`ubuntu@172.25.101.200`, parol: `toor`) `IOT.bin` faylı götürülür və binwalk ilə analizi aparılır.

```bash
scp ubuntu@172.25.101.200:/home/ubuntu/IOT.bin ~/Downloads/
binwalk IOT.bin
# DECIMAL   HEXADECIMAL DESCRIPTION
# 0         0x0         BIN-Header, board ID: 1550, hardware version: 4702, firmware version: 1.0.0
# 32        0x20        TRX firmware header, little endian, header size: 28 bytes
# 60        0x3C        gzip compressed data, original file name: "piggy"
# 1648424   0x192728    Squashfs filesystem, little endian, version 3.0, 447 inodes
```

![IOT.bin Binwalk Analizi](./ch46_50_iot_bin_binwalk.png)

---

#### Challenge 46: IOT.bin Başlığının Başlanğıc Ünvanı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT.bin and find the starting address of the file header. (Answer Format: NxNN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxNN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  TRX firmware başlığının başlanğıc ünvanı `0x20`-dir.
* **Düzgün Cavab:** `0x20`

---

#### Challenge 47: IOT.bin Başlığının Son Ünvanı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT.bin and find the ending address of the file header. (Answer Format: NxNx)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxNx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  TRX başlığı 28 (0x1C) bayt təşkil edir: 0x20 + 0x1C = 0x3C (növbəti bölmənin başlanğıcı). Format tələbinə uyğun: `0x3c`.
* **Düzgün Cavab:** `0x3c`

---

#### Challenge 48: IOT.bin Fayl Sisteminin Başlanğıc Ünvanı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT.bin and find the starting address of the file system. (Answer Format: NxNNNNNN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxNNNNNN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Squashfs fayl sisteminin hex ofseti: `0x192728`.
* **Düzgün Cavab:** `0x192728`

---

#### Challenge 49: gzip Sıxılmış Faylının Adı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT.bin and find the name of the gzip compressed data file. (Answer Format: xxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxxx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Binwalk çıxışında 0x3C ofsetindəki orijinal fayl adı: `piggy`.
* **Düzgün Cavab:** `piggy`

---

#### Challenge 50: IOT.bin Fayl Sisteminin Növü
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT.bin and identify the type of file system in the image. (Answer Format: xxxxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxxxxxx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Fayl sistemi növü: `squashfs`.
* **Düzgün Cavab:** `squashfs`

---

### Hissə 5: CTF 5 - IOT2.bin Analizi (`172.25.101.200`)

Bu hədəfdə Blackfin arxitekturalı Linux Kernel və JFFS2 fayl sistemini ehtiva edən `IOT2.bin` binarı tədqiq edilir.

```bash
scp ubuntu@172.25.101.200:/home/ubuntu/Downloads/IOT2.bin ~/Downloads/
# 100% 26MB 4.5MB/s 00:05

binwalk IOT2.bin
# 0         0x0         uImage header, CPU: Blackfin, image name: "126666"
# 84        0x54        uImage header, script file: "bootscript"
# 352       0x160       uImage header, compression type: gzip, image name: "Linux-2.6.26.5-ADI-2009R1-pre-gd"
# 416       0x1A0       gzip compressed data, maximum compression
# 2097152   0x200000    JFFS2 filesystem, little endian
```

![IOT2.bin Binwalk Analizi](./ch51_55_iot2_binwalk_analysis.png)

---

#### Challenge 51: IOT2.bin gzip Faylının Ünvanı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT2.bin and find the address of the gzip file. (Answer Format: NxNxN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxNxN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Gzip sıxılmış məlumatlarının yerləşdiyi onaltılıq ünvan: `0x1A0`.
* **Düzgün Cavab:** `0x1A0`

---

#### Challenge 52: IOT2.bin uImage Başlığının Ünvanı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT2.bin and find the address of the uImage 66161 header. (Answer Format: NxNNN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxNNN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Gzip-dən əvvəl gələn OS Kernel Image uImage başlığının ünvanı: `0x160`.
* **Düzgün Cavab:** `0x160`

---

#### Challenge 53: Sıxılmış Məlumat Faylının Ölçüsü
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IoT firmware file IOT2.bin and determine the size of the compressed data file. (Answer Format: NN MB)
* **Bal:** 10 Points
* **Cavab Formatı:** `NN MB`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  `scp` ilə köçürülmə zamanı və fayl xüsusiyyətlərində həcm: `26 MB`.
* **Düzgün Cavab:** `26 MB`

---

#### Challenge 54: IOT2.bin Daxilindəki Fayl Sistemi
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT2.bin and find the file system in the image file. (Answer Format: XXXXN)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXXXN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Binwalk 0x200000 ofsetində `JFFS2 filesystem` aşkar edir. Format tələbi `XXXXN` olduğu üçün cavab `JFFS2`-dir.
* **Düzgün Cavab:** `JFFS2`

---

#### Challenge 55: IOT2.bin Fayl Sisteminin Endianness Xüsusiyyəti
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IoT firmware file IOT2.bin and determine the endianness of the file system. (Answer Format: Xxxxxx Xxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxxx Xxxxxx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Binwalk çıxışında qeyd olunur: `JFFS2 filesystem, little endian`. Baş hərflərlə: `Little Endian`.
* **Düzgün Cavab:** `Little Endian`

---

### Hissə 6: CTF 6 - IOT3.bin Sərt Kodlanmış Parolun Tapılması (`172.25.101.200`)

Bu hədəfdə `binwalk -Me --run-as=root IOT3.bin` əmri ilə dərin rekursiv çıxarılma icra edilir və skriptlər daxilində gizlədilmiş autentifikasiya parolu aşkar edilir.

```bash
scp ubuntu@172.25.101.200:/home/ubuntu/Downloads/IOT3.bin ~/Downloads/
binwalk -Me --run-as=root IOT3.bin
cd _IOT3.bin.extracted

find . -type f -name "?????_??????"
# ./_31.extracted/_rootfs.img.extracted/squashfs-root/usr/bin/check_fwmode

strings ./_31.extracted/_rootfs.img.extracted/squashfs-root/usr/bin/check_fwmode | grep -i "pass\|0ee2\|secret"
# eval `REQUEST_METHOD='GET' SCRIPT_NAME='getserviceid.cgi' QUERY_STRING='passwd=0ee2cb110a9148cc5a67f13d62ab64ae30783031' /usr/share/www/cgi-bin/admin/serviceid.cgi | grep serviceid`
```

![IOT3.bin Binwalk Çıxarılması](./ch56_iot3_binwalk_extract.png)
![IOT3.bin Sərt Kodlanmış Parol](./ch57_58_iot3_hardcoded_password.png)

---

#### Challenge 56: IOT3.bin Fayl Sistemi Növü
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT3.bin and determine the file system. (Answer Format: xxxxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxxxxxx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Çıxarılan əsas rootfs fayl sistemi `squashfs`-dir.
* **Düzgün Cavab:** `squashfs`

---

#### Challenge 57: Sərt Kodlanmış Parolu Saxlayan Faylın Adı
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT3.bin and find the file that contains a hardcoded password. (Answer Format: xxxxx_xxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxxx_xxxxxx`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Tələb olunan 5 hərf, alt xətt və 6 hərf formatına (`xxxxx_xxxxxx`) uyğun gələn fayl: `check_fwmode`.
* **Düzgün Cavab:** `check_fwmode`

---

#### Challenge 58: check_fwmode Daxilindəki Sərt Kodlanmış Parol
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT3.bin and find the hardcoded password in the file. (Answer Format: NxxNxxNNNxNNNNxxNxNNxNNxNNxxNNxxNNNNNNNN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NxxNxxNNNxNNNNxxNxNNxNNxNNxxNNxxNNNNNNNN`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  `strings` komandası ilə çıxarılan query string daxilindəki dəyər: `passwd=0ee2cb110a9148cc5a67f13d62ab64ae30783031`.
* **Düzgün Cavab:** `0ee2cb110a9148cc5a67f13d62ab64ae30783031`

---

### Hissə 7: CTF 7 - IOT4.bin HNAP və SOAP Rabitə Tədqiqatı (`172.25.101.200`)

Bu hədəfdə `IOT4.bin` faylı kəsilərək çıxarılır və cihazın idarəetmə və autentifikasiya protokolları təhlil edilir.

```bash
scp ubuntu@172.25.101.200:/home/ubuntu/Downloads/IOT4.bin ~/Downloads/
binwalk IOT4.bin
# 72     0x48    uImage header
# 136    0x88    LZMA compressed data
# 917576 0xE0048 Squashfs filesystem, version 4.0, size: 3531306 bytes

dd if=IOT4.bin of=rootfs.squashfs bs=1 skip=917576
cd _IOT4.bin.extracted/squashfs-root

find . -iname "*hnap*" 2>/dev/null
# ./lib/libhnap.so
# ./usr/local/lib/mod_hnap.so

strings ./lib/libhnap.so | grep -i "soap"
# <SOAPActions>
# <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
```

![IOT4.bin Binwalk İcmalı](./ch59_60_iot4_binwalk_overview.png)
![IOT4.bin HNAP və SOAP Təhlili](./ch59_60_iot4_hnap_soap.png)

---

#### Challenge 59: Cihaz Rabitəsi və Autentifikasiya Protokolu
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT4.bin and find the protocol used for communication to the device and also authentication. (Answer Format: XXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXXX`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  Fayl sistemində `libhnap.so` və `mod_hnap.so` kitabxanaları yerləşir. Bu protokol Home Network Administration Protocol (`HNAP`)-dır.
* **Düzgün Cavab:** `HNAP`

---

#### Challenge 60: Protokolun Aid Olduğu Rabitə Ailəsi
* **Sual (İmtahan Mətni):** On the machine with IP address 172.25.101.200, investigate the IOT firmware file IOT4.bin and find what family is the communication protocol of the device a part of? (Answer Format: XXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXXX`
* **Hədəf:** `172.25.101.200`
* **Metodologiya:**
  `libhnap.so` daxilindəki sətirlərdə `SOAPActions` və `<soap:Envelope>` XML strukturları görünür. HNAP protokolu Simple Object Access Protocol (`SOAP`) ailəsinin tərkib hissəsidir.
* **Düzgün Cavab:** `SOAP`

---

## 3. Nəticə və Xülasə Cədvəli

| Challenge | Hədəf Binar / Sistem               | Kateqoriya           | Sualın Mövzusu                     | Düzgün Cavab                               |
| :-------: | :--------------------------------- | :------------------- | :--------------------------------- | :----------------------------------------- |
|  **26**   | `172.25.101.100` (`FileOne.bin`)   | File Type            | Faylın növü                        | `data`                                     |
|  **27**   | `172.25.101.100` (`FileOne.bin`)   | Header Info          | Firmware versiyası                 | `1.0.0`                                    |
|  **28**   | `172.25.101.100` (`FileOne.bin`)   | Header Info          | Board ID                           | `1550`                                     |
|  **29**   | `172.25.101.100` (`FileOne.bin`)   | Filesystem           | Fayl sistemi növü                  | `squashfs`                                 |
|  **30**   | `172.25.101.100` (`FileOne.bin`)   | Header Info          | Firmware yaradılma tarixi          | `2012-02-08`                               |
|  **31**   | `172.25.101.100` (`FileOne.bin`)   | Filesystem           | İnode sayı                         | `447`                                      |
|  **32**   | `172.25.101.100` (`FileOne.bin`)   | Web Server           | Web səhifəsi genişlənməsi          | `asp`                                      |
|  **33**   | `172.25.101.100` (`FileOne.bin`)   | Services             | /usr/local altındakı xidmət        | `samba`                                    |
|  **34**   | `172.25.101.100` (`FileOne.bin`)   | Vulnerability        | Hücum qovluğu                      | `pwnable`                                  |
|  **35**   | `172.25.101.100` (`FileOne.bin`)   | Architecture         | İstismar CPU arxitekturası         | `MIPS32`                                   |
|  **36**   | `172.25.101.100` (`FileOne.bin`)   | Binary Symbols       | heapoverflow_01 stripped statusu   | `false`                                    |
|  **37**   | `172.25.101.100` (`FileOne.bin`)   | ELF Headers          | heapoverflow_01 program headers    | `6`                                        |
|  **38**   | `172.25.101.100` (`FileOne.bin`)   | ELF Headers          | heapoverflow_01 giriş ünvanı       | `0x400640`                                 |
|  **39**   | `172.25.101.100` (`FileTwo.bin`)   | Filesystem           | Fayl sistemi növü                  | `squashfs`                                 |
|  **40**   | `172.25.101.100` (`FileTwo.bin`)   | Header Info          | CRC son 4 hex rəqəmi               | `E826`                                     |
|  **41**   | `172.25.101.100` (`FileTwo.bin`)   | Cryptanalysis        | Şifrələnmə vəziyyəti               | `False`                                    |
|  **42**   | `172.25.101.100` (`FileTwo.bin`)   | Compression          | Sıxılma vəziyyəti                  | `True`                                     |
|  **43**   | `172.25.101.100` (`FileTwo.bin`)   | Credential Discovery | Root parolunun son 4 simvolu       | `[Laboratoriya xətası / Boş]`              |
|  **44**   | `172.25.101.100` (`FileThree.bin`) | Compression          | Sıxılma vəziyyəti                  | `False`                                    |
|  **45**   | `172.25.101.100` (`FileThree.bin`) | Cryptanalysis        | Şifrələnmə vəziyyəti               | `True`                                     |
|  **46**   | `172.25.101.200` (`IOT.bin`)       | Header Offset        | Başlığın başlanğıc ünvanı          | `0x20`                                     |
|  **47**   | `172.25.101.200` (`IOT.bin`)       | Header Offset        | Başlığın son ünvanı                | `0x3c`                                     |
|  **48**   | `172.25.101.200` (`IOT.bin`)       | Header Offset        | Fayl sisteminin başlanğıc ünvanı   | `0x192728`                                 |
|  **49**   | `172.25.101.200` (`IOT.bin`)       | Compression          | gzip faylının adı                  | `piggy`                                    |
|  **50**   | `172.25.101.200` (`IOT.bin`)       | Filesystem           | Fayl sistemi növü                  | `squashfs`                                 |
|  **51**   | `172.25.101.200` (`IOT2.bin`)      | Header Offset        | gzip faylının ünvanı               | `0x1A0`                                    |
|  **52**   | `172.25.101.200` (`IOT2.bin`)      | Header Offset        | uImage başlığının ünvanı           | `0x160`                                    |
|  **53**   | `172.25.101.200` (`IOT2.bin`)      | Compression          | Sıxılmış faylın ölçüsü             | `26 MB`                                    |
|  **54**   | `172.25.101.200` (`IOT2.bin`)      | Filesystem           | Fayl sistemi növü                  | `JFFS2`                                    |
|  **55**   | `172.25.101.200` (`IOT2.bin`)      | Filesystem           | Fayl sisteminin endianness tipi    | `Little Endian`                            |
|  **56**   | `172.25.101.200` (`IOT3.bin`)      | Filesystem           | Fayl sistemi növü                  | `squashfs`                                 |
|  **57**   | `172.25.101.200` (`IOT3.bin`)      | Credential Discovery | Sərt kodlu parolu saxlayan fayl    | `check_fwmode`                             |
|  **58**   | `172.25.101.200` (`IOT3.bin`)      | Credential Discovery | Sərt kodlu parol                   | `0ee2cb110a9148cc5a67f13d62ab64ae30783031` |
|  **59**   | `172.25.101.200` (`IOT4.bin`)      | Protocols            | Əlaqə və autentifikasiya protokolu | `HNAP`                                     |
|  **60**   | `172.25.101.200` (`IOT4.bin`)      | Protocols            | Protokol ailəsi                    | `SOAP`                                     |
|  **61**   | `172.25.101.100` (`FileThree.bin`) | Compression          | Deşifrə edilmiş sıxılma tipi       | `LZMA`                                     |
