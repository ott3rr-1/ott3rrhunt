# ott3rrhunt
Automated bug bounty reconnaissance tool


# 🦦 Ott3rrHunt

**Automated Bug Bounty Reconnaissance Tool**

*Hunt Smarter, Not Harder*

---

## 📋 Overview

Ott3rrHunt is an all-in-one reconnaissance automation tool designed for bug bounty hunters and penetration testers. It combines multiple industry-standard tools into a streamlined pipeline with three distinct modes: passive, active, and full scanning.

Built for efficiency and ease of use, Ott3rrHunt handles everything from subdomain enumeration to vulnerability scanning, with organized output and real-time progress tracking.

---

## ✨ Features

- 🎯 **Three Scanning Modes**: Passive, Active, and Full
- 🔍 **Multi-Tool Integration**: Subfinder, Assetfinder, Amass, Waybackurls, GAU, HTTPx, Nuclei, FFUF
- 🚀 **Parallel Processing**: Optimized for speed with configurable threads
- 📊 **Pattern Matching**: Automatic detection of XSS, SQLi, SSRF, LFI, RCE patterns
- 🎨 **Interactive Menu**: User-friendly mode selection
- 📁 **Organized Output**: Structured results with timestamps
- ⏱️ **Progress Tracking**: Real-time step completion and elapsed time
- 🛠️ **Easy Installation**: Automated tool installer included

---

## 🎮 Scanning Modes

### 🟢 Passive Mode
**100% stealth reconnaissance - zero target contact**

- Subdomain enumeration via public sources
- Wayback Machine URL collection
- Archive.org data gathering
- Pattern filtering for vulnerabilities
- Parameter extraction

**Use when:** Target restricts active scanning, initial reconnaissance, staying under the radar

### 🟡 Active Mode
**Passive + live host validation + vulnerability scanning**

- All passive features
- Live host probing with HTTPx
- Vulnerability scanning with Nuclei
- Active pattern matching

**Use when:** Target allows active scanning, deeper enumeration needed

### 🔴 Full Mode
**Active + directory fuzzing - most comprehensive**

- All active features
- Directory and path fuzzing with FFUF
- Extensive endpoint discovery

**Use when:** Target explicitly allows aggressive scanning, maximum coverage needed

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ott3rr-1/ott3rrhunt.git
cd ott3rrhunt

# Make scripts executable
chmod +x *.sh

# Run the installer (installs all dependencies)
./install-recon-tools.sh

# Reload your shell
source ~/.zshrc  # or source ~/.bashrc
```

### Basic Usage

```bash
# Interactive mode (recommended for beginners)
./recon-ultimate.sh -d target.com

# Passive mode (safest, no target contact)
./recon-ultimate.sh -d target.com -m passive

# Active mode (probing + scanning)
./recon-ultimate.sh -d target.com -m active -t 15 -j 5

# Full mode (everything including fuzzing)
./recon-ultimate.sh -d target.com -m full -t 15 -j 5 -w /path/to/wordlist.txt
```

---

## 🛠️ Command-Line Options

```
Usage: ./recon-ultimate.sh -d domain [-o outbase] [-w wordlist] [-t threads] [-j jobs] [-m mode]

Options:
  -d domain    : Target domain (required)
  -o outbase   : Base output directory (default: ~/bugbounty/recon)
  -w wordlist  : Wordlist for FFUF directory fuzzing (full mode only)
  -t threads   : Thread count for active tools (default: 15)
  -j jobs      : Parallel jobs for waybackurls (default: 5)
  -m mode      : Scanning mode (passive|active|full) - prompts if not specified
  -h           : Show help message
```

---

## 📦 Requirements

### Core Tools (Required)
- [subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch archived URLs
- [nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner

### Optional Tools (Recommended)
- [assetfinder](https://github.com/tomnomnom/assetfinder) - Additional subdomain discovery
- [amass](https://github.com/OWASP/Amass) - Deep enumeration (works best with API keys)
- [gau](https://github.com/lc/gau) - Get All URLs
- [gf](https://github.com/tomnomnom/gf) - Pattern matching
- [ffuf](https://github.com/ffuf/ffuf) - Web fuzzer
- [anew](https://github.com/tomnomnom/anew) - Append new lines
- [unfurl](https://github.com/tomnomnom/unfurl) - URL parsing

### System Requirements
- Linux or macOS (tested on Kali Linux)
- Go 1.19+ (for tool installation)
- 4GB+ RAM (8GB recommended for active/full modes)
- Bash or Zsh shell

---

## 📊 Output Structure

```
~/bugbounty/recon/
└── target.com/
    └── 20251004-193320/
        ├── subdomains_all.txt           # All discovered subdomains
        ├── subdomains_subfinder.txt     # Subfinder results
        ├── subdomains_assetfinder.txt   # Assetfinder results
        ├── subdomains_amass.txt         # Amass results
        ├── urls_all.txt                 # All archived URLs
        ├── urls_wayback.txt             # Wayback Machine URLs
        ├── urls_gau.txt                 # GAU results
        ├── live.txt                     # Live hosts (active mode)
        ├── nuclei-results.txt           # Vulnerability findings
        ├── ffuf.json                    # Fuzzing results (full mode)
        └── patterns/
            ├── xss.txt                  # XSS candidates
            ├── sqli.txt                 # SQL injection candidates
            ├── ssrf.txt                 # SSRF candidates
            ├── redirect.txt             # Open redirect candidates
            ├── lfi.txt                  # LFI candidates
            ├── rce.txt                  # RCE candidates
            ├── parameters.txt           # Extracted parameters
            └── interesting_extensions.txt # Config/backup files
```

---

## 🔑 API Keys (Optional but Recommended)

Amass works better with API keys. Configure them in `~/.config/amass/config.ini`:

### Free APIs Worth Getting:
- **Shodan** - https://shodan.io/
- **VirusTotal** - https://virustotal.com/
- **SecurityTrails** - https://securitytrails.com/
- **Censys** - https://censys.io/
- **AlienVault OTX** - https://otx.alienvault.com/

Example config:
```ini
[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_SHODAN_KEY

[data_sources.VirusTotal]
[data_sources.VirusTotal.Credentials]
apikey = YOUR_VIRUSTOTAL_KEY
```

---

## 🎯 Workflow Examples

### Example 1: Initial Passive Recon
```bash
# Safe first scan on any bug bounty target
./recon-ultimate.sh -d hackerone.com -m passive

# Review results
cd ~/bugbounty/recon/hackerone.com/[timestamp]/
cat subdomains_all.txt
cat patterns/xss.txt
```

### Example 2: Active Scanning on Authorized Target
```bash
# After verifying target allows active scanning
./recon-ultimate.sh -d target.com -m active -t 20 -j 10

# Check live hosts
cat ~/bugbounty/recon/target.com/[timestamp]/live.txt

# Review vulnerabilities
cat ~/bugbounty/recon/target.com/[timestamp]/nuclei-results.txt
```

### Example 3: Comprehensive Full Scan
```bash
# Maximum coverage with fuzzing
./recon-ultimate.sh -d target.com -m full \
  -t 20 \
  -j 10 \
  -w /usr/share/wordlists/dirb/common.txt
```

---

## 🎨 Customization

### Adjusting for Different Hardware

**For VMs with limited resources (4GB RAM):**
```bash
./recon-ultimate.sh -d target.com -m active -t 10 -j 3
```

**For powerful machines (16GB+ RAM):**
```bash
./recon-ultimate.sh -d target.com -m full -t 30 -j 15
```

### Custom Output Location
```bash
./recon-ultimate.sh -d target.com -m passive -o /custom/path/recon
```

---

## ⚠️ Legal Disclaimer

**IMPORTANT: Only use this tool on authorized targets.**

- ✅ Bug bounty programs with explicit permission
- ✅ Your own infrastructure
- ✅ Authorized penetration testing engagements
- ❌ Unauthorized scanning is illegal

Always:
1. Read the bug bounty program rules
2. Stay within scope
3. Respect rate limits
4. Follow responsible disclosure

**This tool is for educational and authorized security testing only. The author is not responsible for misuse.**

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Improve documentation

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

This tool integrates and automates many excellent open-source projects:
- ProjectDiscovery team (subfinder, httpx, nuclei)
- Tom Hudson / tomnomnom (waybackurls, gf, assetfinder, anew, unfurl)
- OWASP Amass team
- lc (gau)
- ffuf team

---

## 📧 Contact

Created by **Ott3rr**

For questions, issues, or suggestions, please open an issue on GitHub.

---

**Hunt Smarter, Not Harder** 🦦🎯
