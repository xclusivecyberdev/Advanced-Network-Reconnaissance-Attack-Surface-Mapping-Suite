"""Main CLI entry point for the reconnaissance suite."""

import argparse
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from recon_suite import ReconSuite, Config, print_banner
from recon_suite.web.app import run_app


def main():
    """Main CLI entry point."""
    # Print legal banner
    print_banner()

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Advanced Network Reconnaissance & Attack Surface Mapping Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Quick scan
  python -m recon_suite scan --target 192.168.1.1

  # Comprehensive scan with all features
  python -m recon_suite scan --target example.com --scan-type comprehensive --osint --vulnerabilities

  # Stealth scan
  python -m recon_suite scan --target 10.0.0.1 --scan-type stealth

  # Subdomain enumeration
  python -m recon_suite enumerate --domain example.com --bruteforce --osint

  # Start web dashboard
  python -m recon_suite web

⚠️  IMPORTANT: Only scan targets you have explicit permission to test!
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform reconnaissance scan')
    scan_parser.add_argument('--target', '-t', required=True, help='Target (IP, CIDR, domain, URL)')
    scan_parser.add_argument('--scan-type', '-s', choices=['quick', 'standard', 'comprehensive', 'stealth'],
                             default='standard', help='Scan profile (default: standard)')
    scan_parser.add_argument('--ports', '-p', help='Port specification (e.g., 1-1000, 80,443)')
    scan_parser.add_argument('--osint', action='store_true', help='Enable OSINT gathering')
    scan_parser.add_argument('--vulnerabilities', '-v', action='store_true', help='Scan for vulnerabilities')
    scan_parser.add_argument('--output', '-o', help='Output file path')
    scan_parser.add_argument('--format', '-f', choices=['html', 'json', 'pdf', 'csv'],
                             default='html', help='Report format (default: html)')
    scan_parser.add_argument('--parallel', action='store_true', default=True, help='Run scanners in parallel')
    scan_parser.add_argument('--config', '-c', help='Configuration file path')

    # Enumerate command
    enum_parser = subparsers.add_parser('enumerate', help='Enumerate subdomains')
    enum_parser.add_argument('--domain', '-d', required=True, help='Target domain')
    enum_parser.add_argument('--bruteforce', '-b', action='store_true', help='Enable bruteforce enumeration')
    enum_parser.add_argument('--osint', action='store_true', help='Use OSINT sources')
    enum_parser.add_argument('--output', '-o', help='Output file path')

    # Web dashboard command
    web_parser = subparsers.add_parser('web', help='Start web dashboard')
    web_parser.add_argument('--host', default='127.0.0.1', help='Host to bind (default: 127.0.0.1)')
    web_parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    web_parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'scan':
            execute_scan(args)
        elif args.command == 'enumerate':
            execute_enumerate(args)
        elif args.command == 'web':
            execute_web(args)

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


def execute_scan(args):
    """Execute scan command."""
    from colorama import Fore, Style, init
    init()

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Override config with CLI arguments
    if args.ports:
        config.set('scan_profiles.standard.ports', args.ports)

    # Create scanner
    print(f"\n{Fore.CYAN}🎯 Target: {args.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📋 Scan Type: {args.scan_type}{Style.RESET_ALL}\n")

    scanner = ReconSuite(args.target, args.scan_type, config)

    # Run scan
    print(f"{Fore.YELLOW}⏳ Starting scan...{Style.RESET_ALL}\n")
    results = scanner.run(parallel=args.parallel)

    # Print summary
    stats = results.metadata.get('statistics', {})
    print(f"\n{Fore.GREEN}✓ Scan completed!{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}📊 Summary:{Style.RESET_ALL}")
    print(f"  Hosts discovered: {stats.get('total_hosts', 0)}")
    print(f"  Services detected: {stats.get('total_services', 0)}")
    print(f"  Vulnerabilities found: {stats.get('total_vulnerabilities', 0)}")
    print(f"  Technologies detected: {stats.get('total_technologies', 0)}")

    # Generate report
    if args.output or args.format:
        output_file = args.output or f"report_{args.target.replace('/', '_')}.{args.format}"
        print(f"\n{Fore.YELLOW}📄 Generating {args.format.upper()} report...{Style.RESET_ALL}")
        report_path = scanner.generate_report(args.format, output_file)
        print(f"{Fore.GREEN}✓ Report saved: {report_path}{Style.RESET_ALL}\n")


def execute_enumerate(args):
    """Execute subdomain enumeration."""
    from colorama import Fore, Style, init
    from recon_suite.discovery.subdomain_enum import SubdomainEnumerator
    init()

    config = Config()
    print(f"\n{Fore.CYAN}🎯 Domain: {args.domain}{Style.RESET_ALL}\n")

    enumerator = SubdomainEnumerator(config)

    options = {
        'bruteforce': args.bruteforce,
        'osint': args.osint,
    }

    print(f"{Fore.YELLOW}⏳ Enumerating subdomains...{Style.RESET_ALL}\n")
    results = enumerator.scan(args.domain, options)

    # Print results
    subdomains = results.get('results', [])
    print(f"\n{Fore.GREEN}✓ Found {len(subdomains)} subdomains{Style.RESET_ALL}\n")

    for subdomain in subdomains:
        print(f"  {Fore.CYAN}→{Style.RESET_ALL} {subdomain['subdomain']}")
        if subdomain.get('ip_addresses'):
            print(f"    IPs: {', '.join(subdomain['ip_addresses'])}")

    # Save to file if requested
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}✓ Results saved: {args.output}{Style.RESET_ALL}\n")


def execute_web(args):
    """Execute web dashboard."""
    run_app()


if __name__ == '__main__':
    main()
