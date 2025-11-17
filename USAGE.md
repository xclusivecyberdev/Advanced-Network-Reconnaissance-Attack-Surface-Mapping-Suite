  # Usage Guide - Network Reconnaissance Suite

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Command Line Interface](#command-line-interface)
4. [Web Dashboard](#web-dashboard)
5. [Python API](#python-api)
6. [Configuration](#configuration)
7. [Advanced Usage](#advanced-usage)
8. [Best Practices](#best-practices)

## Installation

### Prerequisites
- Python 3.8 or higher
- Root/Administrator privileges (for raw socket operations)
- Internet connection (for OSINT features)

### Basic Installation

```bash
# Clone repository
git clone https://github.com/yourusername/Advanced-Network-Reconnaissance-Attack-Surface-Mapping-Suite.git
cd Advanced-Network-Reconnaissance-Attack-Surface-Mapping-Suite

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
nano .env  # Edit configuration
```

### Package Installation

```bash
pip install -e .
```

## Quick Start

### 1. Basic Scan

```bash
# Scan single host
sudo python -m recon_suite scan --target 192.168.1.1

# Scan network
sudo python -m recon_suite scan --target 192.168.1.0/24 --scan-type quick
```

### 2. Domain Reconnaissance

```bash
# Full domain scan with OSINT
python -m recon_suite scan --target example.com --scan-type comprehensive --osint
```

### 3. Subdomain Enumeration

```bash
# Enumerate subdomains
python -m recon_suite enumerate --domain example.com --bruteforce --osint
```

### 4. Web Dashboard

```bash
# Start web interface
python -m recon_suite web
# Navigate to http://127.0.0.1:5000
# Default login: admin / changeme
```

## Command Line Interface

### Scan Command

```bash
python -m recon_suite scan [OPTIONS]
```

#### Options:

| Option | Description | Example |
|--------|-------------|---------|
| `--target, -t` | Target to scan (required) | `-t 192.168.1.1` |
| `--scan-type, -s` | Scan profile | `-s comprehensive` |
| `--ports, -p` | Port specification | `-p 1-1000` or `-p 80,443` |
| `--osint` | Enable OSINT gathering | `--osint` |
| `--vulnerabilities, -v` | Scan for vulnerabilities | `-v` |
| `--output, -o` | Output file path | `-o report.html` |
| `--format, -f` | Report format | `-f json` |
| `--config, -c` | Configuration file | `-c config.yaml` |

#### Scan Profiles:

- **quick**: Fast scan of common ports (21-25, 80, 443, etc.)
- **standard**: Balanced scan of ports 1-1000 with service detection
- **comprehensive**: Deep scan of all ports with OS detection and vulnerabilities
- **stealth**: Slow, evasive scan with timing delays

### Examples

```bash
# Quick web server scan
sudo python -m recon_suite scan -t example.com -s quick -p 80,443,8080

# Comprehensive network scan
sudo python -m recon_suite scan -t 10.0.0.0/24 -s comprehensive -v -f html -o network_report.html

# Stealth scan with custom ports
sudo python -m recon_suite scan -t 192.168.1.100 -s stealth -p 1-65535

# Full reconnaissance with OSINT
python -m recon_suite scan -t example.com -s comprehensive --osint --vulnerabilities
```

### Enumerate Command

```bash
python -m recon_suite enumerate --domain example.com [OPTIONS]
```

#### Options:

| Option | Description |
|--------|-------------|
| `--domain, -d` | Target domain (required) |
| `--bruteforce, -b` | Enable bruteforce enumeration |
| `--osint` | Use OSINT sources |
| `--output, -o` | Output file path |

#### Examples:

```bash
# Subdomain enumeration with all methods
python -m recon_suite enumerate -d example.com --bruteforce --osint

# OSINT-only enumeration
python -m recon_suite enumerate -d example.com --osint -o subdomains.json
```

## Web Dashboard

### Starting the Dashboard

```bash
# Default (127.0.0.1:5000)
python -m recon_suite web

# Custom host and port
python -m recon_suite web --host 0.0.0.0 --port 8080

# Debug mode
python -m recon_suite web --debug
```

### Features

- **Authentication**: Secure login system
- **Scan Management**: Create and manage scans
- **Real-time Monitoring**: Watch scans progress
- **Report Export**: Export to HTML, JSON, PDF, CSV
- **Visualization**: Charts and graphs of results

### Default Credentials

- **Username**: `admin`
- **Password**: `changeme`

**⚠️ Important**: Change the default password immediately after first login!

## Python API

### Basic Usage

```python
from recon_suite import ReconSuite, Config

# Create scanner
scanner = ReconSuite(
    target="192.168.1.1",
    scan_type="standard"
)

# Run scan
results = scanner.run(parallel=True)

# Generate report
scanner.generate_report('html', 'report.html')

# Access results
print(f"Found {len(results.hosts)} hosts")
print(f"Found {len(results.services)} services")
print(f"Found {len(results.vulnerabilities)} vulnerabilities")
```

### Advanced Usage

```python
from recon_suite import ReconSuite, Config

# Custom configuration
config = Config()
config.set('scanning.max_threads', 100)
config.set('scanning.rate_limit_delay', 0.05)

# Create scanner with config
scanner = ReconSuite(
    target="example.com",
    scan_type="comprehensive",
    config=config
)

# Enable specific modules
scanner.enabled_modules['subdomain_enum'] = True
scanner.enabled_modules['vulnerability_scan'] = True

# Run scan
results = scanner.run(parallel=True)

# Access detailed results
for host in results.hosts:
    print(f"Host: {host['host']}")
    for port in host.get('ports', []):
        print(f"  Port {port['port']}: {port['service']}")

for vuln in results.vulnerabilities:
    print(f"Vulnerability: {vuln['cve_id']} - {vuln['severity']}")
```

### Using Individual Scanners

```python
from recon_suite.scanners import PortScanner
from recon_suite.passive import DNSEnumerator
from recon_suite.fingerprinting import BannerGrabber
from recon_suite.core.config import Config

config = Config()

# Port scanning
port_scanner = PortScanner(config)
port_results = port_scanner.scan("192.168.1.1", {'ports': '1-1000'})

# DNS enumeration
dns_enum = DNSEnumerator(config)
dns_results = dns_enum.scan("example.com")

# Banner grabbing
banner_grabber = BannerGrabber(config)
banner_results = banner_grabber.scan("192.168.1.1", {'open_ports': [80, 443]})
```

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# API Keys
SHODAN_API_KEY=your_api_key_here
VIRUSTOTAL_API_KEY=your_api_key_here

# Database
DATABASE_URL=sqlite:///recon_suite.db

# Flask
FLASK_SECRET_KEY=your_secret_key_here
FLASK_HOST=127.0.0.1
FLASK_PORT=5000

# Scanning
MAX_CONCURRENT_SCANS=10
MAX_THREADS=50
RATE_LIMIT_DELAY=0.1
```

### Configuration File

Create `config.yaml`:

```yaml
scanning:
  max_threads: 50
  rate_limit_delay: 0.1
  scan_timeout: 3600

scan_profiles:
  custom:
    ports: '1-10000'
    timing: 'normal'
    service_detection: true
    os_detection: true

osint:
  enabled_sources:
    - dns
    - whois
    - ssl_certificates
    - shodan
```

Use with:
```bash
python -m recon_suite scan -t example.com -c config.yaml
```

## Advanced Usage

### Custom Plugins

Create custom scanner plugin:

```python
# my_plugin.py
from recon_suite.plugins import ScannerPlugin

class MyCustomScanner(ScannerPlugin):
    def __init__(self):
        super().__init__(name="MyCustomScanner", version="1.0")

    def scan(self, target, options=None):
        # Your scanning logic here
        results = []

        # Example: custom check
        result = {
            'target': target,
            'check': 'custom_check',
            'status': 'passed'
        }
        results.append(result)

        return {
            'scanner': self.name,
            'results': results
        }
```

### Batch Scanning

```python
from recon_suite import ReconSuite

targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']

for target in targets:
    scanner = ReconSuite(target, 'quick')
    results = scanner.run()
    scanner.generate_report('json', f'report_{target}.json')
```

### Filtering Results

```python
results = scanner.run()

# Get only critical vulnerabilities
critical_vulns = [
    v for v in results.vulnerabilities
    if v['severity'] == 'CRITICAL'
]

# Get services on specific ports
web_services = [
    s for s in results.services
    if s['port'] in [80, 443, 8080]
]
```

## Best Practices

### Legal and Ethical

1. **Always get written permission** before scanning
2. **Stay within scope** of authorized testing
3. **Document all activities** for audit trail
4. **Respect rate limits** to avoid disruption
5. **Use VPN** for additional privacy (when authorized)

### Technical

1. **Start with quick scans** before comprehensive ones
2. **Use appropriate timing** for network conditions
3. **Save results** after each scan
4. **Review logs** for errors or anomalies
5. **Update CVE database** regularly

### Performance

1. **Limit concurrent scans** based on system resources
2. **Use parallel scanning** for multiple targets
3. **Adjust thread count** based on network capacity
4. **Monitor system resources** during scans
5. **Use stealth mode** only when necessary (it's slower)

### Security

1. **Change default passwords** immediately
2. **Use strong API keys** for external services
3. **Encrypt sensitive data** in reports
4. **Limit network access** to dashboard
5. **Review permissions** before deployment

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo for raw socket access
sudo python -m recon_suite scan -t 192.168.1.1
```

**Module Not Found**
```bash
# Solution: Install in development mode
pip install -e .
```

**Timeout Errors**
```python
# Solution: Increase timeout in config
config.set('scanning.scan_timeout', 7200)  # 2 hours
```

**Too Many Open Files**
```bash
# Solution: Increase file descriptor limit
ulimit -n 4096
```

## Support

- **Documentation**: See README.md
- **Issues**: Report at GitHub Issues
- **Security**: Email security@example.com
