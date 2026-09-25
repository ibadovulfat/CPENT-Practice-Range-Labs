# CPENT Live Range - CTF Linux & System Penetration Testing Walkthrough & Solution Guide

> **Sənəd Növü:** Senior Penetration Tester & Linux Red Team Texniki Hesabatı  
> **Hədəf Mühit:** CPENT CTF Range (192.168.1.0/24)  
> **Suallar:** Challenge 100 - Challenge 118  
> **Tərtib Edən:** Senior Pentester & Security Engineer  

---

## 1. Giriş və CTF Şəbəkə Topologiyası

CPENT CTF zonası Linux əsaslı müxtəlif zəiflikləri, xidmət səhvlərini və Privilege Escalation vektorlarını (Sudo GTFOBins, SUID proqramlar, RSYNC açıq modulları, Kernel istismarı, PwnKit və Base64 şifrələnmiş SSH açarları) ehtiva edir.

### Hədəf Maşınların Xəritəsi

| Hədəf IP | Açıq Portlar / Xidmətlər | İlkin Giriş Vektoru | İcazə Qaldırma (PrivEsc) | Əlaqəli Suallar |
| :--- | :--- | :--- | :--- | :--- |
| `192.168.1.104` | 22 (SSH) | Hydra SSH Brute-Force (`rebecca`) | Sudo `/home/rebecca/python3` GTFOBins | Challenge 100 - 103 |
| `192.168.1.105` | 8000 (TCP Service) | Şəbəkə xidməti üzərindən giriş | Sudo `/home/suiduser/userperl` GTFOBins | Challenge 104 - 107 |
| `192.168.1.136` | 873 (RSYNC) | Anonim RSYNC Modul Kəşfiyyatı | Fayl sinxronizasiyası (`flag.txt`) | Challenge 108 - 109 |
| `192.168.1.130` | 80 (HTTP), 22 (SSH) | Online Book Store 1.0 RCE | SSH `id_rsa` (parol: `smile`), Kernel Exploit | Challenge 110 - 112 |
| `192.168.1.128` | 80 (HTTP) | Job Portal 1.0 RCE | PwnKit (CVE-2021-4034) ilə root keçidi | Challenge 113 - 114 |
| `192.168.1.151` | 80 (HTTP), 22 (SSH), 3000 (Git) | `killmyeye.php` üzərindən LFI / Key Read | Base64 RSA açarı ilə SSH Root girişi | Challenge 115 - 118 |

---

## 2. CTF Tapşırıqlarının Ətraflı Həlli (Q100 - Q118)

---

### Hədəf 1: Rebecca Virtual Machine (`192.168.1.104`)

#### Challenge 100: Rebecca İstifadəçisinin SSH Şifrəsi
* **Sual (İmtahan Mətni):** What is the password that lets you remotely login to the machine 192.168.1.104? (Answer format: xxxxxxNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxNNN`
* **Hədəf:** `192.168.1.104` (SSH 22)
* **Metodologiya:**
  `hydra` vasitəsilə SSH xidmətinə qarşı lüğət hücumu təşkil edilir:
  ```bash
  hydra -L Usernames.txt -P Passwords.txt 192.168.1.104 ssh -t 16 -f
  ```
  Aşkar olunan etibarnamə: `rebecca` : `qwerty123`.
* **Düzgün Cavab:** `qwerty123`

#### Challenge 101: Rebecca İstifadəçi Bayrağı (userflag.txt)
* **Sual (İmtahan Mətni):** Compromise 192.168.1.104 and enter the value of userflag.txt. (Answer format: xxNxxxNNxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxNxxxNNxx`
* **Hədəf:** `192.168.1.104`
* **Metodologiya:**
  SSH ilə qoşulub istifadəçi ev qovluğundakı bayraq oxunur:
  ```bash
  cat /home/rebecca/userflag.txt
  ```
  Çıxış: `jk3hfp86fg`.
* **Düzgün Cavab:** `jk3hfp86fg`
* **Əlaqəli Şəkil:**
  
  ![Rebecca SSH və Userflag](./ch100_102_rebecca_ssh_userflag.png)

#### Challenge 102: Rebecca üçün İcazə Verilmiş Sudo Binarı
* **Sual (İmtahan Mətni):** Identify the binary that helps in attaining escalated privileges on 192.168.1.104. (Answer format: xxxxxxN)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxN`
* **Hədəf:** `192.168.1.104`
* **Metodologiya:**
  `sudo -l` sorğusu icra edilir:
  ```text
  User rebecca may run the following commands on ubuntu-Virtual-Machine:
      (root) NOPASSWD: /home/rebecca/python3
  ```
  İcazə verilən binar proqram: `python3`.
* **Düzgün Cavab:** `python3`
* **Əlaqəli Şəkil:**
  
  ![Rebecca Sudo Python3](./ch100_102_rebecca_ssh_userflag.png)

#### Challenge 103: Rebecca Maşınında Root Bayrağı (rootflag.txt)
* **Sual (İmtahan Mətni):** Compromise 192.168.1.104 and enter the value of rootflag.txt. (Answer format: XxxxxxxNxxNxN)
* **Bal:** 100 Points
* **Cavab Formatı:** `XxxxxxxNxxNxN`
* **Hədəf:** `192.168.1.104`
* **Metodologiya:**
  Python3 GTFOBins texnikası ilə root hüquqları əldə edilir və rootflag tapılır:
  ```bash
  sudo /home/rebecca/python3 -c 'import pty; pty.spawn("/bin/bash")'
  cat /etc/kernel/rootflag.txt
  ```
  Çıxış: `Skillch3ck3d1`.
* **Düzgün Cavab:** `Skillch3ck3d1`
* **Əlaqəli Şəkil:**
  
  ![Rootflag Skillch3ck3d1](./ch103_rebecca_python_rootflag.png)

---

### Hədəf 2: Suiduser Virtual Machine (`192.168.1.105`)

#### Challenge 104: 192.168.1.105 İstifadəçi Adı
* **Sual (İmtahan Mətni):** Identify the username of the currently logged-in user after obtaining the initial shell on 192.168.1.105. (Answer format: xxxxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxxx`
* **Hədəf:** `192.168.1.105:8000`
* **Metodologiya:**
  8000-ci portdakı xidmətə qoşulub sessiya əldə edildikdə `id` əmri ilə cari istifadəçi müəyyən edilir:
  `uid=1001(suiduser) gid=1001(svcuser)` -> `suiduser`.
* **Düzgün Cavab:** `suiduser`
* **Əlaqəli Şəkil:**
  
  ![Suiduser Terminal Session](./ch104_105_suiduser_session_userflag.png)

#### Challenge 105: Suiduser Userflag.txt Dəyəri
* **Sual (İmtahan Mətni):** Compromise 192.168.1.105 and enter the value of userflag.txt. (Answer format: xxNxxNNNx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxNxxNNNx`
* **Hədəf:** `192.168.1.105`
* **Metodologiya:**
  ```bash
  cat /home/suiduser/userflag.txt
  ```
  Çıxış: `hf4km956g`.
* **Düzgün Cavab:** `hf4km956g`
* **Əlaqəli Şəkil:**
  
  ![Suiduser Userflag](./ch104_105_suiduser_session_userflag.png)

#### Challenge 106: Suiduser üçün İcazə Verilmiş Sudo Proqramı
* **Sual (İmtahan Mətni):** Identify the binary that helps in attaining escalated privileges on 192.168.1.105. (Answer format: xxxxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxxxxxx`
* **Hədəf:** `192.168.1.105`
* **Metodologiya:**
  `sudo -l` çıxışında icazə verilən komanda:
  `(root) NOPASSWD: /home/suiduser/userperl` -> `userperl`.
* **Düzgün Cavab:** `userperl`
* **Əlaqəli Şəkil:**
  
  ![Sudo userperl Command](./ch106_107_userperl_rootflag.png)

#### Challenge 107: 192.168.1.105 Rootflag.txt Dəyəri
* **Sual (İmtahan Mətni):** Compromise 192.168.1.105 and enter the value of rootflag.txt. (Answer format: xNNxxxxNxN)
* **Bal:** 100 Points
* **Cavab Formatı:** `xNNxxxxNxN`
* **Hədəf:** `192.168.1.105`
* **Metodologiya:**
  Perl vasitəsilə root komanda sətri açılır və root bayrağı oxunur:
  ```bash
  sudo /home/suiduser/userperl -e 'exec "/bin/bash"'
  cat /home/ubuntu/rootflag.txt
  ```
  Çıxış: `p76dwmz8c9`.
* **Düzgün Cavab:** `p76dwmz8c9`
* **Əlaqəli Şəkil:**
  
  ![Rootflag p76dwmz8c9](./ch106_107_userperl_rootflag.png)

---

### Hədəf 3: RSYNC Modul Təhlükəsizliyi (`192.168.1.136`)

#### Challenge 108: Açıq RSYNC Modulunun Adı
* **Sual (İmtahan Mətni):** Identify the shared directory accessible via the Rsync service running on the machine located at 192.168.1.136. (Answer Format: Xxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `Xxxxx`
* **Hədəf:** `192.168.1.136:873`
* **Metodologiya:**
  RSYNC xidməti sorğulanır və autentifikasiyasız əlçatan modul aşkarlanır:
  ```bash
  rsync rsync://192.168.1.136
  ```
  Aşkar olunan modul: `James`.
* **Düzgün Cavab:** `James`
* **Əlaqəli Şəkil:**
  
  ![RSYNC Modul Siyahısı](./ch108_109_rsync_module_flag.png)

#### Challenge 109: 192.168.1.136 Üzərində Flag.txt Məzmunu
* **Sual (İmtahan Mətni):** What is the value that is found on the flag.txt on the machine located at 192.168.1.136? (Answer Format: xXNxxNxXxxXx)
* **Bal:** 100 Points
* **Cavab Formatı:** `xXNxxNxXxxXx`
* **Hədəf:** `192.168.1.136`
* **Metodologiya:**
  RSYNC vasitəsilə `flag.txt` faylı birbaşa yerli maşına endirilir:
  ```bash
  rsync -av rsync://192.168.1.136/James/flag.txt ./flag.txt
  cat flag.txt
  ```
  Çıxış: `jN5fn8rYnuAj`.
* **Düzgün Cavab:** `jN5fn8rYnuAj`
* **Əlaqəli Şəkillər:**
  
  ![RSYNC Flag Endirilməsi](./ch108_109_rsync_module_flag.png)
  ![Challenge 109 Sual Görünüşü](./ch110_111_kernel_version_userflag.png)

---

### Hədəf 4: Online Book Store & Kernel İstismarı (`192.168.1.130`)

#### Challenge 110: Hədəf Sistemin Nüvə (Kernel) Versiyası
* **Sual (İmtahan Mətni):** Determine the kernel version of the target system located at 192.168.1.130. (Answer Format: N.N.N-NNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `N.N.N-NNN`
* **Hədəf:** `192.168.1.130`
* **Metodologiya:**
  Sistemdə `uname -r` icra edilərək nüvə versiyası yoxlanılır: `4.4.0-116`.
* **Düzgün Cavab:** `4.4.0-116`
* **Əlaqəli Şəkillər:**
  
  ![Bookstore Directory Audit](./ch110_bookstore_directory_audit.png)
  ![Kernel Version Info](./ch110_111_kernel_version_userflag.png)

#### Challenge 111: 192.168.1.130 User.txt Məzmunu
* **Sual (İmtahan Mətni):** What is the value present in the file user.txt on the machine located at 192.168.1.130? (Answer Format: NxxxNNxN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NxxxNNxN`
* **Hədəf:** `192.168.1.130`
* **Metodologiya:**
  1. `cyberq_user` istifadəçisinin ev qovluğunda `user.txt` oxunur: `2cbe65d4`.
  2. SSH açarı (`id_rsa`) John The Ripper ilə sındırılır: parol `smile`.
* **Düzgün Cavab:** `2cbe65d4`
* **Əlaqəli Şəkillər:**
  
  ![User Flag 2cbe65d4](./ch110_111_kernel_version_userflag.png)
  ![John the Ripper Crack smile](./ch111_john_ssh_key_crack.png)

#### Challenge 112: 192.168.1.130 Root.txt Məzmunu
* **Sual (İmtahan Mətni):** What is the value present in the file root.txt on the machine located at 192.168.1.130? (Answer Format: xNNxNxNN)
* **Bal:** 100 Points
* **Cavab Formatı:** `xNNxNxNN`
* **Hədəf:** `192.168.1.130`
* **Metodologiya:**
  Ubuntu Kernel 4.4.0-116 üçün uyğun gələn yerli hüquq artırma istismarı tətbiq olunur və `/root/root.txt` oxunur:
  Çıxış: `d61e0a87`.
* **Düzgün Cavab:** `d61e0a87`
* **Əlaqəli Şəkil:**
  
  ![Root Flag d61e0a87](./ch112_kernel_exploit_rootflag.png)

---

### Hədəf 5: Job Portal və PwnKit (`192.168.1.128`)

#### Challenge 113: 192.168.1.128 User.txt Dəyəri
* **Sual (İmtahan Mətni):** What is the value present in the file user.txt on the machine located at 192.168.1.128?(Answer Format: NNNNNNxN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNNNNxN`
* **Hədəf:** `192.168.1.128`
* **Metodologiya:**
  `nagios` istifadəçisinin ev qovluğunda yerləşən `user.txt` faylı oxunur: `014891b2`.
* **Düzgün Cavab:** `014891b2`
* **Əlaqəli Şəkil:**
  
  ![Nagios User Flag](./ch113_114_jobportal_pwnkit_flags.png)

#### Challenge 114: 192.168.1.128 Root.txt Dəyəri
* **Sual (İmtahan Mətni):** What is the value present in the file root.txt on the machine located at 192.168.1.128?(Answer Format: NNNxNNxx)
* **Bal:** 100 Points
* **Cavab Formatı:** `NNNxNNxx`
* **Hədəf:** `192.168.1.128`
* **Metodologiya:**
  Sistemdə yoxlanılan PwnKit zəifliyi vasitəsilə root hüquqları əldə edilir və `/root/root.txt` oxunur: `215f83bf`.
* **Düzgün Cavab:** `215f83bf`
* **Əlaqəli Şəkillər:**
  
  ![Root Flag 215f83bf](./ch113_114_jobportal_pwnkit_flags.png)
  ![Challenge 114 Sual və Nəticə](./ch116_118_gitport_ssh_rootflag.png)

---

### Hədəf 6: killmyeye.php & Base64 RSA Açar (`192.168.1.151`)

#### Challenge 115: Base64 Şifrəli Açardan Son 5 Simvol
* **Sual (İmtahan Mətni):** The machine 192.168.1.151 contains an SSH private key. Identify the key and submit the last five characters of its Base64-encoded content, found between the BEGIN and END key tags. (Answer Format: NxXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `NxXXX`
* **Hədəf:** `192.168.1.151`
* **Metodologiya:**
  `http://192.168.1.151/killmyeye.php` səhifəsində `/root/.ssh/id_rsa` sorğulanır. Alınan Base64 məzmunun son 5 simvolu: `5oMBD`.
* **Düzgün Cavab:** `5oMBD`
* **Əlaqəli Şəkillər:**
  
  ![killmyeye.php Endpoint](./ch115_killmyeye_ssh_key.png)
  ![CyberChef Base64 Decode](./ch115_117_cyberchef_base64.png)
  ![Challenge 115 Sual Təsviri](./ch116_118_gitport_ssh_rootflag.png)

#### Challenge 116: Git Xidmətinin İşlədiyi Port
* **Sual (İmtahan Mətni):** Identify the port on which Git service is running on the machine 192.168.1.151. (Answer Format: NNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `192.168.1.151`
* **Metodologiya:**
  Port skanı zamanı xüsusi Git veb xidmətinin (məsələn, Gogs/Gitea) 3000-ci portda işlədiyi aşkar olunur.
* **Düzgün Cavab:** `3000`
* **Əlaqəli Şəkil:**
  
  ![Challenge 116 Git Port Sualı](./ch116_118_gitport_ssh_rootflag.png)

#### Challenge 117: Şəxsi Açarla Əlaqəli Kodlaşdırma Formatı
* **Sual (İmtahan Mətni):** Determine the encoding format of the private key on the machine located at 192.168.1.151.(Answer Format: XxxxNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `XxxxNN`
* **Hədəf:** `192.168.1.151`
* **Metodologiya:**
  Veb formadan çıxarılan açarın kodlaşdırılma formatı: `Base64`.
* **Düzgün Cavab:** `Base64`
* **Əlaqəli Şəkillər:**
  
  ![CyberChef Base64 Analizi](./ch115_117_cyberchef_base64.png)
  ![Challenge 117 Sual Təsviri](./ch116_118_gitport_ssh_rootflag.png)

#### Challenge 118: 192.168.1.151 Root.txt Dəyəri
* **Sual (İmtahan Mətni):** Retrieve the value present in the file named root.txt on the machine located at 192.168.1.151. (Answer Format:xNxxxNNx)
* **Bal:** 100 Points
* **Cavab Formatı:** `xNxxxNNx`
* **Hədəf:** `192.168.1.151`
* **Metodologiya:**
  Decode olunmuş `id_rsa` açarı ilə root kimi SSH sessiyası açılır:
  ```bash
  ssh -i id_rsa root@192.168.1.151 -t '/bin/sh'
  cat /root/root.txt
  ```
  Çıxış: `c6eef85e`.
* **Düzgün Cavab:** `c6eef85e`
* **Əlaqəli Şəkil:**
  
  ![SSH Root Access və Flag](./ch116_118_gitport_ssh_rootflag.png)

---

## 3. CTF Range Xülasə Cədvəli

| Sual # | Hədəf IP | Zəiflik / Vektor | Düzgün Cavab | İstifadə Olunan Əsas Alət |
| :---: | :--- | :--- | :--- | :--- |
| **100** | `192.168.1.104` | Zəif SSH Şifrəsi | `qwerty123` | Hydra SSH |
| **101** | `192.168.1.104` | İstifadəçi Ev Qovluğu | `jk3hfp86fg` | SSH Login, Cat |
| **102** | `192.168.1.104` | Sudo NOPASSWD İcazəsi | `python3` | `sudo -l` |
| **103** | `192.168.1.104` | Python PTY Spawn PrivEsc | `Skillch3ck3d1` | `/etc/kernel/rootflag.txt` |
| **104** | `192.168.1.105` | Şəbəkə Servisi Girişi | `suiduser` | `id` əmri |
| **105** | `192.168.1.105` | İstifadəçi Bayrağı | `hf4km956g` | `/home/suiduser/userflag.txt` |
| **106** | `192.168.1.105` | Sudo İcazəsi | `userperl` | `sudo -l` |
| **107** | `192.168.1.105` | Perl Exec Root Keçidi | `p76dwmz8c9` | `/home/ubuntu/rootflag.txt` |
| **108** | `192.168.1.136` | Anonim RSYNC Modulu | `James` | `rsync rsync://...` |
| **109** | `192.168.1.136` | Açıq Fayl Sinxronizasiyası | `jN5fn8rYnuAj` | `rsync -av` |
| **110** | `192.168.1.130` | Köhnəlmiş Linux Kernel | `4.4.0-116` | `uname -r` |
| **111** | `192.168.1.130` | Zəif SSH Açar Passphrase | `2cbe65d4` | John the Ripper (`smile`) |
| **112** | `192.168.1.130` | Kernel İstismarı | `d61e0a87` | Root shell, `/root/root.txt` |
| **113** | `192.168.1.128` | Web RCE / Nagios Girişi | `014891b2` | `/home/nagios/user.txt` |
| **114** | `192.168.1.128` | PwnKit İstismarı | `215f83bf` | `/root/root.txt` |
| **115** | `192.168.1.151` | Fayl Oxunması Zəifliyi | `5oMBD` | `killmyeye.php`, Base64 |
| **116** | `192.168.1.151` | Git Xidmət Portu | `3000` | Nmap Port Scan |
| **117** | `192.168.1.151` | Açar Kodlaşdırması | `Base64` | CyberChef Analizi |
| **118** | `192.168.1.151` | Şəxsi Açar ilə SSH Girişi | `c6eef85e` | `ssh -i id_rsa root@...` |

---

## 4. Təhlükəsizlik və Remediation Tövsiyələri

1. **SSH və Giriş Təhlükəsizliyi:** SSH xidmətində parol əsaslı autentifikasiya söndürülməli (`PasswordAuthentication no`), güclü SSH açarları və mütləq şifrələnmiş passphrase tətbiq olunmalıdır.
2. **Xidmət İcazələrinin Məhdudlaşdırılması:** RSYNC (`rsyncd.conf`) xidmətlərində `hosts allow`, `auth users` və gizli modullar təyin edilməli, anonim oxuma icazəsi dərhal ləğv olunmalıdır.
3. **Nüvə və Paket Yeniləmələri (Patch Management):** Bütün Linux hostlarında nüvə vaxtında yenilənməli, PwnKit və oxşar təhlükəli SUID binar zəiflikləri ən son repozitoriya yamaları ilə bağlanmalıdır.
4. **Sudo Siyasəti:** İstifadəçilərə proqramlaşdırma dilləri (`python`, `perl`, `awk`) üzrə `sudo NOPASSWD` hüququ verilməməlidir.
