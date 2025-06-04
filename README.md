### **cyber-security-trainer**

## 5 main chapters it covers
|sr. no.| Chapter Name                                     | Total Topics experiments|
|-------|--------------------------------------------------|-------------------------|
|1. |N/W Security & Introduction and Fundamentals   -  CH1 | total EXPS= 3|
|2. |cyber securiy System Prevention or protection  -  CH2 | total EXPS= 6|
|3. |N/W threats and Hacking Simulation             -  CH3 | total EXPS= 7|
|4. |Cryptography                                   -  CH4 | total EXPS= 5|
|5. |IOT Cloud Security                             -  CH5 | total EXPS= 1|

## How to build executable from python script

- It requires pyinstaller library so install it using command `pip3 install pyinstaller`
- Use this command for building executable `pyinstaller --noconfirm --onefile --windowed  "<path-to-scrpt.py>"`
- Alternatively auto-py-to-exe can be used but above steps recommended.

## How to Run python scripts and bash script

- Use commands `python3 <file_name.py>` or `bash <file_name.sh>

## Distribution format for linux PC based application use PD 16/32 GB PD to transfer files from DVD to Linux PC:-


| Sr No. | Parameter     | Github Repository | Production DVD    | Accompanying DVD | Project DVD |
|--------|---------------|-------------------|------------------|-----------------|------------|
|   1    | Executables   |     .py code      |      App/.exe    |       -         |     Backup     |
|   2    | Scripts       |      Codes        |      Codes       |       -         |     Backup     |
|   4    | Admin App     |   .py Code + App  |     App/.exe      |       -         |     Backup     |
|   6    | Config txt    |  H/W Config list  |H/W Config list   |       -         |     Backup     |
|   7    | lib folder    |   NA - Too Big    |Dnloaded lib Codes|       -         |     Backup     |
|   8    | requirements  | List of libraries |      -           |       -         |     Backup     |
|   9    | Wireshark     |      -            |      -           |  Installer      |     Backup     |
| 10     |Linux ISO      |     NA | Linux ISO DVD containing Imager & 2 ISOs| -   |     Backup     | 


## Directory listing FOR PRODUCTION DVD ---
Note:-
- 1. Production DVD Consists of Executables folder, Scripts folder , config.txt, lib folder, Admin app(only EXE)
- 2. Executables folder contains apps(.exe) whose actual python codes are saved in CSEH_Code folder. 
```
F:\>dir
 Volume in drive F is XPO-CSEH PROD CD
 Volume Serial Number is 9126-FF0F
 Directory of F:\
18-04-2025  15:51    <DIR>          XPO-CSEH production cd
               0 File(s)              0 bytes
               1 Dir(s)               0 bytes free
 Directory of F:\XPO-CSEH production cd
18-04-2025  15:51    <DIR>          .
19-04-2025  13:51    <DIR>          ..
18-04-2025  10:13         7,991,472 Admin
06-02-2025  15:31        58,328,249 Easy Smart Configuration Utility v1.3.19.0.exe.zip
19-05-2025  11:35    <DIR>          Executables
19-05-2025  11:35    <DIR>          Scripts
16-04-2025  07:19             1,225 config.txt
18-04-2025  15:56    <DIR>          lib
               3 File(s)     66,320,946 bytes
               5 Dir(s)               0 bytes free
 Directory of F:\XPO-CSEH production cd\Executables
19-05-2025  11:35    <DIR>          .
18-04-2025  15:51    <DIR>          ..
19-05-2025  11:35    <DIR>          Authentication Apps
19-05-2025  11:35    <DIR>          Cryptography Apps
19-05-2025  11:35    <DIR>          DOS Apps
19-05-2025  11:35    <DIR>          IOT Apps
19-05-2025  11:35    <DIR>          Introduction Apps
19-05-2025  11:35    <DIR>          Spoofing Apps
19-05-2025  11:35    <DIR>          VPN Apps
19-05-2025  11:35    <DIR>          Virus Apps
               0 File(s)              0 bytes
              10 Dir(s)               0 bytes free
 Directory of F:\XPO-CSEH production cd\Scripts
19-05-2025  11:35    <DIR>          .
18-04-2025  15:51    <DIR>          ..
19-05-2025  11:35    <DIR>          Antivirus Scripts
19-05-2025  11:35    <DIR>          Authentication Web
19-05-2025  11:35    <DIR>          Firewall Scripts
19-05-2025  11:35    <DIR>          Hoax-Spyware Scripts
19-05-2025  11:35    <DIR>          IDSnIPS Scripts
19-05-2025  11:35    <DIR>          Introduction Scripts
19-05-2025  11:35    <DIR>          Phishing Codes
19-05-2025  11:35    <DIR>          SQLi Codes
19-05-2025  11:35    <DIR>          SSL-n-TLS Scripts
19-05-2025  11:35    <DIR>          Spoofing Scripts
19-05-2025  11:35    <DIR>          Virus Codes
               0 File(s)              0 bytes
              13 Dir(s)               0 bytes free

```
  -------------   END DVD            
