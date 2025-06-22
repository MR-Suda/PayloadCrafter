# PayloadCrafter 💀
> RTX Cyber Warfare Module – Automated Payload Builder  
> **By MR-Suda**

---

## ⚔️ Overview

**PayloadCrafter** is a Bash-based automation tool designed for cybersecurity professionals, red teamers, and ethical hackers.  
It simplifies the process of generating Metasploit payloads using `msfvenom`, sets up listeners, and optionally hosts the payloads via Apache for phishing or social engineering operations.

---

## 🚀 Features

- 🔥 **Automated payload generation** using `msfvenom`
- 🎯 Supports **staged** and **stageless** Meterpreter payloads for:
  - Windows
  - Linux
  - Android
  - macOS
- 🛠️ **Advanced options selector** (AutoRunScript, PrependMigrate, UUID tracking, etc.)
- ⚙️ Optional **EXE template injection** via `-x` and `-k`
- 🌐 **Apache hosting integration** for payload delivery
- 🧠 Intelligent error detection and safe cleanup on crashes
- 📜 Auto-generated `msfconsole` listener script (`.rc`)

---

## 📦 Supported Payloads

| ID  | Payload                                     | Type      |
|-----|---------------------------------------------|-----------|
| 1   | `windows/meterpreter/reverse_tcp`           | Staged    |
| 2   | `windows/meterpreter/reverse_http`          | Staged    |
| 3   | `linux/x86/meterpreter/reverse_tcp`         | Staged    |
| 4   | `android/meterpreter/reverse_tcp`           | Staged    |
| 5   | `windows/x64/meterpreter/reverse_https`     | Staged    |
| 6   | `windows/meterpreter_reverse_tcp`           | Stageless |
| 7   | `windows/x64/shell_reverse_tcp`             | Stageless |
| 8   | `linux/x64/shell_reverse_tcp`               | Stageless |
| 9   | `osx/x64/shell_reverse_tcp`                 | Stageless |
| 10  | Custom Payload Input                        | Custom    |

---

## 🧪 Usage

1. Clone or download the script:
   ```bash
   git clone https://github.com/MR-Suda/PayloadCrafter.git
   cd PayloadCrafter

    Give it executable permissions or run with bash:

chmod +x PayloadCrafter.sh

Run the script with root privileges:

    sudo ./PayloadCrafter.sh

    Follow the on-screen prompts:

        Select a payload

        Enter LHOST and LPORT

        Choose a format and (optional) EXE template

        Set advanced options

        Generate and host your payload

🛡️ Requirements

    Kali Linux or any Linux with:

        msfvenom (Metasploit Framework)

        apache2 (optional for hosting)

        sudo access

🧼 Safe Exit & Cleanup

The script gracefully handles:

    Ctrl+C interruptions

    msfvenom generation failures

    Apache shutdown on crash

    Temporary file cleanup

📁 Output Files
File	Purpose
payload_*.exe	Generated payload
msfvenom_output.txt	Logs msfvenom output
listener_*.rc	Auto-launch listener script
📜 License

This project is released for educational and ethical use only.
⚠️ Unauthorized or malicious usage is strictly prohibited.
✍️ Author

    💀 MR-Suda
    ⚙️ Cyber Warfare & Red Team Tools
    📫 GitHub Profile

⭐ Star this repo if it helped you!

---

Let me know if you want to include usage screenshots or a badge-style header (e.g., Bash, Kali, MIT License). I can generate those too.
