# Quick Start Guide

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env

# Optional: Install as package
pip install -e .
```

## Basic Usage

### 1. Quick Scan (Recommended for Testing)

```bash
# Scan a single host (requires sudo for raw sockets)
sudo python -m recon_suite scan --target scanme.nmap.org --scan-type quick
```

### 2. Comprehensive Domain Scan

```bash
# Full reconnaissance with OSINT
python -m recon_suite scan --target example.com --scan-type comprehensive --osint
```

### 3. Subdomain Enumeration

```bash
# Discover subdomains using multiple methods
python -m recon_suite enumerate --domain example.com --bruteforce --osint --output subdomains.json
```

### 4. Web Dashboard

```bash
# Start web interface
python -m recon_suite web

# Access at: http://127.0.0.1:5000
# Login: admin / changeme
```

## Example Commands

```bash
# Quick web server check
sudo python -m recon_suite scan -t example.com -s quick -p 80,443,8080 -f html -o report.html

# Network scan with vulnerability detection
sudo python -m recon_suite scan -t 192.168.1.0/24 -s standard -v -f json -o network_scan.json

# Stealth scan
sudo python -m recon_suite scan -t 10.0.0.1 -s stealth -p 1-1000

# Full OSINT reconnaissance
python -m recon_suite scan -t company.com --osint --vulnerabilities -f pdf -o company_report.pdf
```

## Python API Example

```python
from recon_suite import ReconSuite

# Create scanner
scanner = ReconSuite(target="example.com", scan_type="standard")

# Run scan
results = scanner.run(parallel=True)

# Generate report
scanner.generate_report('html', 'report.html')

# Access results
print(f"Hosts: {len(results.hosts)}")
print(f"Services: {len(results.services)}")
print(f"Vulnerabilities: {len(results.vulnerabilities)}")
```

## Safety Checklist

Before running any scans:

- [ ] I have written permission to scan the target
- [ ] I understand the legal implications
- [ ] I have configured rate limits appropriately
- [ ] I am scanning within authorized scope
- [ ] I have backups of important data

## Common Issues

**Permission Denied**: Run with `sudo` for network scans
**Module Not Found**: Run `pip install -e .`
**Timeout Errors**: Increase timeout in .env file

## Next Steps

1. Read [USAGE.md](USAGE.md) for detailed documentation
2. Configure API keys in `.env` for enhanced features
3. Explore the web dashboard for visual interface
4. Customize scan profiles in configuration

## Support

For questions or issues, please see the README.md or open an issue on GitHub.
