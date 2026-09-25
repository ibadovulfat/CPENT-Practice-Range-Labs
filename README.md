# EC-Council CPENT Live Practice Range - Complete Walkthrough & Solutions

[![CPENT](https://img.shields.io/badge/Certification-CPENT-red.svg)](https://www.eccouncil.org/programs/certified-penetration-testing-professional-cpent/)
[![LPT Master](https://img.shields.io/badge/Track-LPT%20Master-blue.svg)](https://www.eccouncil.org/)
[![Status](https://img.shields.io/badge/Coverage-100%25%20(130%20Challenges)-brightgreen.svg)]()
[![Documentation](https://img.shields.io/badge/Reports-Azerbaijani%20%7C%20English-orange.svg)]()

This repository contains comprehensive step-by-step walkthroughs, penetration testing methodologies, exploit scripts, terminal commands, and verified screenshot evidence for all 5 zones (130 Challenges) of the official **EC-Council Certified Penetration Testing Professional (CPENT)** Live Practice Range.

All challenge solutions are thoroughly documented in both **English** and **Azerbaijani**.

---

## 📌 Table of Contents

- [About The Repository](#-about-the-repository)
- [⚡ Quick Access: Direct Lab Walkthroughs (English)](#-quick-access-direct-lab-walkthroughs-english)
  - [1. Binary Analysis & Exploit Development (Ch 01 - 25)](Binary/binary_range_EN.md)
  - [2. IoT & Firmware Analysis (Ch 26 - 61)](IOT/IOT_range_EN.md)
  - [3. Active Directory Range (Ch 62 - 99)](AD/AD_range_EN.md)
  - [4. Capture The Flag (CTF) Range (Ch 100 - 118)](CTF/CTF_range_EN.md)
  - [5. Web Application Penetration Testing (Ch 119 - 129)](WEB/Web_range_EN.md)
- [Practice Range Overview & Matrix](#-practice-range-overview--matrix)
- [Directory Structure](#-directory-structure)
- [Range Breakdowns](#-range-breakdowns)
  - [1. Binary Analysis & Exploit Development (Ch 01 - 25)](#1-binary-analysis--exploit-development-ch-01---25---open-en-walkthrough-)
  - [2. IoT & Firmware Analysis (Ch 26 - 61)](#2-iot--firmware-analysis-ch-26---61---open-en-walkthrough-)
  - [3. Active Directory Range (Ch 62 - 99)](#3-active-directory-range-ch-62---99---open-en-walkthrough-)
  - [4. Capture The Flag (CTF) Range (Ch 100 - 118)](#4-capture-the-flag-ctf-range-ch-100---118---open-en-walkthrough-)
  - [5. Web Application Penetration Testing (Ch 119 - 129)](#5-web-application-penetration-testing-ch-119---129---open-en-walkthrough-)
- [Tools & Technologies](#-tools--technologies)
- [Ethical Disclaimer](#-ethical-disclaimer)
- [Contact & Connect](#-contact--connect)

---

## 📖 About The Repository

The EC-Council CPENT (and its prestigious LPT Master track) is recognized as one of the most demanding hands-on penetration testing certifications. The live practice range requires candidates to execute complex multi-vector attacks across enterprise networks, pivot through restricted subnets, develop custom memory corruption exploits, reverse-engineer proprietary IoT firmware, and fully compromise multi-forest Active Directory infrastructures.

This repository serves as a centralized technical knowledge base and walkthrough guide covering the entire range:
- Complete coverage from **Challenge 01 through Challenge 129**
- Exact target answer formats and verified challenge keys
- Reproducible command-line steps and proof-of-concept exploits
- Visual verification with organized, high-resolution screenshots

---

## ⚡ Quick Access: Direct Lab Walkthroughs (English)

Click any of the links below to directly open the complete English walkthrough report for that specific range:

- 🔬 [**Binary Range Walkthrough (Ch 01 - 25)**](Binary/binary_range_EN.md) - CesarFTP exploit dev, Ghidra, GDB, EIP offset, checksec, ROP
- 📡 [**IoT Range Walkthrough (Ch 26 - 61)**](IOT/IOT_range_EN.md) - Binwalk, SquashFS/JFFS2, MIPS32, XOR decryption, TRX/uImage, HNAP/SOAP
- 🏢 [**Active Directory Range Walkthrough (Ch 62 - 99)**](AD/AD_range_EN.md) - Kerberos enum, Kerberoasting, AS-REP roasting, NetExec, Domain Trusts, DC compromise
- 🚩 [**CTF Range Walkthrough (Ch 100 - 118)**](CTF/CTF_range_EN.md) - SSH brute-force, SUID privesc, Rsync, Linux kernel exploits, PwnKit, CyberChef
- 🌐 [**Web Range Walkthrough (Ch 119 - 129)**](WEB/Web_range_EN.md) - OTRS exploit, SQL Injection DB dump, AWK injection, Burp file upload, SUID find

---

## 🎯 Practice Range Overview & Matrix

| Range Area | Challenges | Count | English Walkthrough | Azerbaijani Report | Key Focus & Techniques |
| :--- | :---: | :---: | :---: | :---: | :--- |
| [**Binary Range**](Binary/binary_range_EN.md) | Challenge 01 - 25 | 25 | [📖 Open Walkthrough](Binary/binary_range_EN.md) | [🇦🇿 Open Report](Binary/binary_range_AZ.md) | CesarFTP exploit dev, Ghidra static analysis, checksec, GDB, EIP offset, ROP gadgets, Linux & Windows privilege escalation |
| [**IoT Range**](IOT/IOT_range_EN.md) | Challenge 26 - 61 | 36 | [📖 Open Walkthrough](IOT/IOT_range_EN.md) | [🇦🇿 Open Report](IOT/IOT_range_AZ.md) | Binwalk firmware unpacking, SquashFS/JFFS2 extraction, MIPS32 binary analysis, XOR decryption, TRX/uImage headers, HNAP/SOAP |
| [**Active Directory Range**](AD/AD_range_EN.md) | Challenge 62 - 99 | 38 | [📖 Open Walkthrough](AD/AD_range_EN.md) | [🇦🇿 Open Report](AD/AD_range_AZ.md) | Kerberos user enumeration, Kerberoasting, AS-REP roasting, NetExec, BloodHound, Domain Trusts, CU12 SPN, ACL bypass, DC compromise |
| [**CTF Range**](CTF/CTF_range_EN.md) | Challenge 100 - 118 | 19 | [📖 Open Walkthrough](CTF/CTF_range_EN.md) | [🇦🇿 Open Report](CTF/CTF_range_AZ.md) | SSH brute-forcing, SUID binary exploitation, Rsync misconfigurations, Linux Kernel exploits, PwnKit, CyberChef, Git root flags |
| [**Web Range**](WEB/Web_range_EN.md) | Challenge 119 - 129 | 11 | [📖 Open Walkthrough](WEB/Web_range_EN.md) | [🇦🇿 Open Report](WEB/Web_range_AZ.md) | OTRS ticketing exploit, SQL Injection DB dump, AWK command execution, Burp upload filter bypass, SUID find, WP cron abuse |
| **Total** | **Challenge 01 - 129** | **129** | **5 English Walkthroughs** | **5 Azerbaijani Reports** | **100% Full CPENT Practice Range Coverage** |

---

## 📂 Directory Structure

```text
CPENT-range/
│
├── AD/                                 # Active Directory Range (Challenge 62 - 99)
│   ├── AD_range_EN.md                  # Comprehensive English Walkthrough
│   ├── AD_range_AZ.md                  # Comprehensive Azerbaijani Walkthrough
│   └── ch62_...png - ch99_...png       # 34 Verified Challenge Screenshots
│
├── Binary/                             # Binary & Exploit Development (Challenge 01 - 25)
│   ├── binary_range_EN.md              # Technical English Walkthrough
│   ├── binary_range_AZ.md              # Technical Azerbaijani Walkthrough
│   └── ch01_...png - ch25_...png       # 15 Verified Challenge Screenshots
│
├── CTF/                                # CTF & Linux Privilege Escalation (Challenge 100 - 118)
│   ├── CTF_range_EN.md                 # Full English Walkthrough
│   ├── CTF_range_AZ.md                 # Full Azerbaijani Walkthrough
│   └── ch100_...png - ch118_...png     # 13 Verified Challenge Screenshots
│
├── IOT/                                # IoT & Firmware Reverse Engineering (Challenge 26 - 61)
│   ├── IOT_range_EN.md                 # Comprehensive English Walkthrough
│   ├── IOT_range_AZ.md                 # Comprehensive Azerbaijani Walkthrough
│   └── ch26_...png - ch61_...png       # 18 Verified Challenge Screenshots
│
├── WEB/                                # Web Application Penetration Testing (Challenge 119 - 129)
│   ├── Web_range_EN.md                 # Full English Walkthrough
│   ├── Web_range_AZ.md                 # Full Azerbaijani Walkthrough
│   └── ch119_...png - ch129_...png     # 7 Verified Challenge Screenshots
│
├── LICENSE                             # Proprietary & Confidential License Terms
├── .gitignore                          # Git Exclusion Rules (Obsidian, OS, Python artifacts)
└── README.md                           # Main Repository Documentation & Direct Navigation
```

---

## 🔍 Range Breakdowns

### 1. Binary Analysis & Exploit Development (Ch 01 - 25) - [Open EN Walkthrough ↗](Binary/binary_range_EN.md)
- **Targets:** Remote daemon exploitation, local binary reverse engineering, memory corruption.
- **Key Techniques & Milestones:**
  - CesarFTP 0.99g `MKD` buffer overflow vulnerability analysis and custom exploit scripting in Python.
  - SSH service auditing on non-standard ports (Port 60000) and automated credential attacks.
  - Static disassembly and decompilation using **Ghidra** (locating `main`, function symbols, hardcoded strings, and logic flaws).
  - Inspecting binary defense mitigations via **checksec** (NX, PIE, Stack Canaries, RELRO).
  - Dynamic debugging using **GDB (GEF / PEDA)**: pattern generation (`pattern create 100`), crash offset determination (`pattern offset 64`), register overwrites (EIP / RIP), and bad character detection.
  - Exploiting the `one.exe` binary and local privilege escalation.

### 2. IoT & Firmware Analysis (Ch 26 - 61) - [Open EN Walkthrough ↗](IOT/IOT_range_EN.md)
- **Targets:** Embedded system firmware images (`FileOne.bin`, `FileTwo.bin`, `FileThree.bin`, `IOT.bin`, `IOT2.bin`, `IOT3.bin`, `IOT4.bin`).
- **Key Techniques & Milestones:**
  - Firmware component extraction with `binwalk` and file system mounting (SquashFS, JFFS2).
  - Reverse engineering MIPS32 binaries (`heapoverflow_01` stripped status, program headers, entry points).
  - Firmware entropy visualization to detect encrypted versus compressed data blocks.
  - Breaking custom XOR-encrypted firmware (`FileThree.bin`) using key recovery scripts and frequency analysis (8-byte XOR key).
  - Parsing TRX and uImage headers to determine raw offsets, kernel sizes, and compression formats (LZMA, gzip).
  - Extracting embedded administrative credentials, backdoors, and configuration files (`check_fwmode`).
  - Auditing IoT communication protocols: HNAP (Home Network Administration Protocol) and SOAP XML APIs.

### 3. Active Directory Range (Ch 62 - 99) - [Open EN Walkthrough ↗](AD/AD_range_EN.md)
- **Targets:** Enterprise-grade Windows Active Directory domain environments (`LPT.COM`, `CPENT.COM`).
- **Key Techniques & Milestones:**
  - Pre-auth user enumeration via Kerberos (`kerbrute`, Nmap `krb5-enum-users.realm`).
  - SPN harvesting and **Kerberoasting** attacks (`GetUserSPNs.py`).
  - AS-REP Roasting for accounts with `DONT_REQ_PREAUTH` enabled.
  - Domain trust mapping using `nltest /domain_trusts` and `netdom query trust`.
  - Comprehensive Active Directory object enumeration (OUs, security groups, ACLs, BloodHound).
  - SMB Signing validation and relay assessment using `NetExec` (`nxc`) and `crackmapexec`.
  - Lateral movement and administrative execution across Windows Server 2008, 2012, 2019, 2022, and workstation endpoints via PsExec, Pass-the-Hash, and SMB credential brute-forcing.
  - ACL abuse for privilege escalation and full Domain Controller takeover.

### 4. Capture The Flag (CTF) Range (Ch 100 - 118) - [Open EN Walkthrough ↗](CTF/CTF_range_EN.md)
- **Targets:** Hardened Linux targets requiring deep multi-stage exploitation.
- **Key Techniques & Milestones:**
  - Service enumeration and brute-forcing exposed SSH services.
  - SUID binary exploitation (leveraging custom scripts and `userperl`).
  - Discovering and abusing misconfigured, unauthenticated Rsync daemon modules to exfiltrate and overwrite system files.
  - Kernel vulnerability identification and local root escalation via **PwnKit** (CVE-2021-4034).
  - Password cracking with John the Ripper and Hashcat using custom rule sets (`ssh2john`).
  - Multi-stage decoding of obfuscated data using CyberChef and recovering SSH keys from hidden Git repositories.

### 5. Web Application Penetration Testing (Ch 119 - 129) - [Open EN Walkthrough ↗](WEB/Web_range_EN.md)
- **Targets:** Enterprise ticketing platforms, proprietary database backends, and CMS deployments.
- **Key Techniques & Milestones:**
  - OTRS (Open Ticket Request System) web application exploitation leading to system compromise.
  - In-depth SQL Injection (SQLi) exploitation: extracting databases, schema layouts, table structures, and sensitive password hashes.
  - Post-exploitation command execution leveraging the `awk` utility.
  - Bypassing file upload restrictions using Burp Suite to deploy interactive PHP web shells.
  - Privilege escalation through misconfigured SUID binaries (`find` exec).
  - Exploiting scheduled WordPress cron jobs and vulnerable plugin architectures.

---

## 🛠️ Tools & Technologies

| Domain | Tools & Frameworks |
| :--- | :--- |
| **Reconnaissance & Network** | Nmap, NetExec (nxc), CrackMapExec, RPCClient, Smbclient, Medusa |
| **Active Directory Exploitation** | Kerbrute, Impacket (`GetUserSPNs.py`, `psexec.py`, `secretsdump.py`), BloodHound, nltest, netdom |
| **Binary Analysis & Exploitation** | Ghidra, GDB (GEF / PEDA), checksec, readelf, ropper, objdump, Python (`socket` / `struct`) |
| **IoT & Firmware Analysis** | Binwalk, Firmware-Mod-Kit (FMK), xortool, dd, sasquatch, file, hexdump |
| **Web Application Security** | Burp Suite Professional, SQLMap, Gobuster, Nikto, cURL |
| **Password Cracking & Cryptography** | John the Ripper, Hashcat, CyberChef, base64 |

---

## ⚖️ Ethical Disclaimer

The material, methodologies, scripts, and walkthroughs contained in this repository are published strictly for **educational, academic, and authorized lab practice purposes only**. Performing unauthorized attacks against systems without explicit prior written consent from the target system owner is illegal and violates local, state, federal, and international cybercrime laws. The author assumes no liability and is not responsible for any misuse or damage caused by the information provided herein.

---

## 📬 Contact & Connect

Feel free to connect or reach out for inquiries, discussions, or professional collaboration:

- **LinkedIn:** [https://www.linkedin.com/in/ibadovulfat/](https://www.linkedin.com/in/ibadovulfat/)
- **Site:** [https://about.surf](https://about.surf/)
