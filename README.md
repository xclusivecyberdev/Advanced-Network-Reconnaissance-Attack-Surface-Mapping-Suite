# Advanced Network Reconnaissance & Attack Surface Mapping Suite

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-production--grade-brightgreen.svg)]()

A comprehensive, production-grade network reconnaissance and attack surface mapping tool designed for authorized security assessments, penetration testing, and defensive security operations.

## ⚠️ Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This tool is designed for **authorized security testing only**. Users must:

- ✅ Have explicit written permission to scan target networks
- ✅ Comply with all applicable laws and regulations
- ✅ Use only in authorized penetration testing, CTF competitions, or defensive security contexts
- ✅ Respect rate limits and avoid causing disruption

**UNAUTHORIZED USE IS ILLEGAL**. The developers assume NO liability for misuse. By using this tool, you agree to use it responsibly and legally.

## 🚀 Features

### Active Scanning
- **SYN/ACK/UDP Scanning** using Scapy and python-nmap
- **Port Discovery** with configurable scan profiles
- **OS Fingerprinting** and TTL analysis
- **Firewall Detection** and evasion techniques

### Passive Reconnaissance
- **DNS Enumeration** (A, AAAA, MX, TXT, NS, SOA records)
- **WHOIS Lookup** with registrar information
- **SSL/TLS Certificate Analysis** with chain validation
- **Search Engine OSINT** integration
- **Public Archive Mining** (Wayback Machine, Certificate Transparency)
- **Shodan Integration** for internet-wide asset discovery

### Service Fingerprinting
- **Banner Grabbing** for all common protocols
- **Version Detection** with CPE matching
- **TLS Handshake Parsing** (cipher suites, protocols, extensions)
- **HTTP Security Headers** (HSTS, HPKP, CSP, X-Frame-Options)
- **Certificate Chain Analysis** with expiration tracking

### Technology Detection
- **HTTP Header Fingerprinting**
- **Favicon Hash Matching** (Shodan/OWASP methodology)
- **Wappalyzer-style Signatures** (1000+ technologies)
- **CMS Detection** (WordPress, Joomla, Drupal, etc.)
- **Framework Identification** (React, Angular, Django, etc.)

### Discovery & Expansion
- **Subdomain Enumeration** (bruteforce + OSINT sources)
- **Cloud Asset Discovery** (AWS, Azure, GCP)
- **ASN Lookup** and BGP routing information
- **CIDR Expansion** for network mapping
- **Reverse DNS** sweeps

### Vulnerability Analysis
- **CVE Matching** against detected versions
- **CPE-based Lookup** using NIST NVD database
- **Configuration Weakness Detection**
- **SSL/TLS Vulnerability Checks** (POODLE, Heartbleed, etc.)
- **Risk Scoring** with CVSS integration

### Reporting & Visualization
- **HTML Reports** with interactive charts
- **JSON Export** for automation
- **PDF Generation** with executive summaries
- **CSV Export** for spreadsheet analysis
- **Network Topology Diagrams**
- **Risk Heat Maps**

### Web Dashboard
- **Authentication System** with session management
- **Real-time Scan Monitoring** with WebSocket updates
- **Interactive Charts** using Plotly
- **Scan History** and comparison
- **Asset Inventory** management
- **Export Options** from web interface

## 📋 Requirements

- Python 3.8+
- Linux/macOS (Windows partially supported)
- Root/Administrator privileges (for raw socket operations)
- 2GB+ RAM recommended
- Internet connection (for OSINT features)

## 🔧 Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/Advanced-Network-Reconnaissance-Attack-Surface-Mapping-Suite.git
cd Advanced-Network-Reconnaissance-Attack-Surface-Mapping-Suite
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configuration

```bash
cp .env.example .env
# Edit .env with your API keys and configuration
nano .env
```

### 5. Initialize Database

```bash
python -m recon_suite.database.init_db
```

### 6. Download CVE Database (Optional)

```bash
python -m recon_suite.vulnerability.download_cve_db
```

## 🎯 Usage

### Command Line Interface

#### Basic Scan
```bash
sudo python -m recon_suite scan --target 192.168.1.0/24
```

#### Full Reconnaissance
```bash
sudo python -m recon_suite scan --target example.com \
    --scan-type full \
    --ports 1-65535 \
    --osint \
    --vulnerabilities \
    --output-format html,json
```

#### Stealth Scan
```bash
sudo python -m recon_suite scan --target 10.0.0.1 \
    --scan-type syn \
    --timing paranoid \
    --randomize
```

#### Subdomain Enumeration
```bash
python -m recon_suite enumerate --domain example.com \
    --bruteforce \
    --osint-sources all
```

### Web Dashboard

```bash
python -m recon_suite.web.app
```

Then navigate to `http://127.0.0.1:5000` in your browser.

Default credentials:
- Username: `admin`
- Password: `changeme` (change on first login!)

### Python API

```python
from recon_suite import ReconSuite

# Initialize scanner
scanner = ReconSuite(
    target="192.168.1.1",
    scan_type="comprehensive",
    enable_osint=True
)

# Run scan
results = scanner.run()

# Generate report
scanner.generate_report(results, format="html", output="report.html")
```

## 🏗️ Architecture

```
recon_suite/
├── core/              # Core scanning engine
├── scanners/          # Active scanning modules
├── passive/           # Passive reconnaissance
├── fingerprinting/    # Service & technology detection
├── discovery/         # Subdomain & asset discovery
├── vulnerability/     # CVE mapping & analysis
├── reporting/         # Report generation
├── web/              # Web dashboard
├── database/         # Data persistence
├── utils/            # Utility functions
└── plugins/          # Extensible plugin system
```

## 🔌 Plugin System

Create custom plugins by extending the base classes:

```python
from recon_suite.plugins import ScannerPlugin

class CustomScanner(ScannerPlugin):
    def __init__(self):
        super().__init__(name="Custom Scanner", version="1.0")

    def scan(self, target, options):
        # Your scanning logic here
        return results
```

## 📊 Example Reports

The suite generates comprehensive reports including:

- Executive Summary with risk overview
- Detailed host inventory
- Open ports and services
- Detected vulnerabilities with CVE references
- Technology stack analysis
- Network topology visualization
- Remediation recommendations

## 🛡️ Safety Features

- **Rate Limiting** to prevent network flooding
- **Timeout Controls** for hung scans
- **Permission Checks** before executing
- **Legal Banners** on startup
- **Audit Logging** of all activities
- **Graceful Error Handling**

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- Nmap project for port scanning inspiration
- OWASP for security testing methodologies
- Wappalyzer for technology signatures
- NIST NVD for CVE database

## 📧 Contact

For questions, issues, or security concerns, please open an issue on GitHub.

## 🔐 Security

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker.

---

**Remember: With great power comes great responsibility. Use ethically and legally!**
