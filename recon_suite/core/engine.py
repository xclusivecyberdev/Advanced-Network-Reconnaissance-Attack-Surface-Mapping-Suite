"""Core reconnaissance engine orchestrating all scanning modules."""

import logging
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import traceback

from .config import Config
from .scanner_base import ScanResult
from ..utils.logger import setup_logger
from ..utils.validators import validate_target, normalize_target


class ReconSuite:
    """Main reconnaissance suite engine."""

    def __init__(self, target: str, scan_type: str = 'standard', config: Optional[Config] = None):
        """
        Initialize reconnaissance suite.

        Args:
            target: Target to scan (IP, CIDR, domain, URL)
            scan_type: Scan profile (quick, standard, comprehensive, stealth)
            config: Configuration object
        """
        self.target = target
        self.scan_type = scan_type
        self.config = config or Config()
        self.logger = setup_logger('ReconSuite', self.config)
        self.results = ScanResult(target, scan_type)
        self.scanners = []
        self.enabled_modules = {
            'port_scan': True,
            'service_detection': True,
            'os_fingerprint': False,
            'banner_grabbing': True,
            'dns_enum': True,
            'whois': True,
            'ssl_analysis': True,
            'subdomain_enum': False,
            'technology_detection': True,
            'vulnerability_scan': False,
            'osint': False,
        }

        # Update modules based on scan type
        self._configure_scan_profile()

        # Initialize scanners
        self._initialize_scanners()

    def _configure_scan_profile(self):
        """Configure enabled modules based on scan profile."""
        profile = self.config.get(f'scan_profiles.{self.scan_type}', {})

        if self.scan_type == 'quick':
            self.enabled_modules.update({
                'os_fingerprint': False,
                'subdomain_enum': False,
                'vulnerability_scan': False,
                'osint': False,
            })
        elif self.scan_type == 'comprehensive':
            self.enabled_modules.update({
                'os_fingerprint': True,
                'subdomain_enum': True,
                'vulnerability_scan': True,
                'osint': True,
            })
        elif self.scan_type == 'stealth':
            self.enabled_modules.update({
                'os_fingerprint': False,
                'banner_grabbing': False,
            })

        self.logger.info(f"Configured scan profile: {self.scan_type}")

    def _initialize_scanners(self):
        """Initialize all scanner modules."""
        try:
            # Import scanner modules
            from ..scanners.port_scanner import PortScanner
            from ..scanners.service_detector import ServiceDetector
            from ..passive.dns_enum import DNSEnumerator
            from ..passive.whois_lookup import WhoisLookup
            from ..passive.ssl_analyzer import SSLAnalyzer
            from ..fingerprinting.banner_grabber import BannerGrabber
            from ..fingerprinting.technology_detector import TechnologyDetector

            # Add scanners based on enabled modules
            if self.enabled_modules.get('port_scan'):
                self.scanners.append(PortScanner(self.config))

            if self.enabled_modules.get('service_detection'):
                self.scanners.append(ServiceDetector(self.config))

            if self.enabled_modules.get('banner_grabbing'):
                self.scanners.append(BannerGrabber(self.config))

            if self.enabled_modules.get('dns_enum'):
                self.scanners.append(DNSEnumerator(self.config))

            if self.enabled_modules.get('whois'):
                self.scanners.append(WhoisLookup(self.config))

            if self.enabled_modules.get('ssl_analysis'):
                self.scanners.append(SSLAnalyzer(self.config))

            if self.enabled_modules.get('technology_detection'):
                self.scanners.append(TechnologyDetector(self.config))

            if self.enabled_modules.get('subdomain_enum'):
                from ..discovery.subdomain_enum import SubdomainEnumerator
                self.scanners.append(SubdomainEnumerator(self.config))

            if self.enabled_modules.get('vulnerability_scan'):
                from ..vulnerability.cve_scanner import CVEScanner
                self.scanners.append(CVEScanner(self.config))

            self.logger.info(f"Initialized {len(self.scanners)} scanner modules")

        except ImportError as e:
            self.logger.warning(f"Failed to import some scanners: {e}")

    def run(self, parallel: bool = True) -> ScanResult:
        """
        Execute reconnaissance scan.

        Args:
            parallel: Run scanners in parallel if True

        Returns:
            ScanResult object with all findings
        """
        self.logger.info(f"Starting reconnaissance on {self.target}")
        start_time = datetime.utcnow()

        # Validate target
        if not validate_target(self.target):
            raise ValueError(f"Invalid target: {self.target}")

        # Normalize target
        normalized_target = normalize_target(self.target)
        self.logger.info(f"Normalized target: {normalized_target}")

        try:
            if parallel:
                self._run_parallel()
            else:
                self._run_sequential()

            # Post-processing
            self._post_process_results()

        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.logger.debug(traceback.format_exc())
            raise

        finally:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            self.results.metadata['duration'] = duration
            self.results.metadata['scan_completed'] = True
            self.logger.info(f"Scan completed in {duration:.2f} seconds")

        return self.results

    def _run_parallel(self):
        """Run scanners in parallel using thread pool."""
        max_workers = min(len(self.scanners), self.config.get('scanning.max_threads', 10))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_scanner = {
                executor.submit(self._execute_scanner, scanner): scanner
                for scanner in self.scanners
            }

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    result = future.result()
                    self._merge_results(result)
                except Exception as e:
                    self.logger.error(f"Scanner {scanner.name} failed: {e}")

    def _run_sequential(self):
        """Run scanners sequentially."""
        for scanner in self.scanners:
            try:
                result = self._execute_scanner(scanner)
                self._merge_results(result)
            except Exception as e:
                self.logger.error(f"Scanner {scanner.name} failed: {e}")

    def _execute_scanner(self, scanner) -> Dict[str, Any]:
        """
        Execute a single scanner.

        Args:
            scanner: Scanner instance to execute

        Returns:
            Scanner results
        """
        self.logger.info(f"Executing {scanner.name}")

        try:
            # Pre-scan
            if not scanner.pre_scan(self.target):
                raise Exception(f"Pre-scan validation failed for {scanner.name}")

            # Execute scan
            scan_options = self._get_scanner_options(scanner.name)
            result = scanner.scan(self.target, scan_options)

            # Post-scan
            final_result = scanner.post_scan()

            return final_result

        except Exception as e:
            self.logger.error(f"Scanner {scanner.name} error: {e}")
            self.logger.debug(traceback.format_exc())
            return {'scanner': scanner.name, 'error': str(e), 'results': []}

    def _get_scanner_options(self, scanner_name: str) -> Dict[str, Any]:
        """Get scanner-specific options from config."""
        profile = self.config.get(f'scan_profiles.{self.scan_type}', {})
        return profile

    def _merge_results(self, scanner_result: Dict[str, Any]):
        """
        Merge scanner results into main results.

        Args:
            scanner_result: Results from individual scanner
        """
        scanner_name = scanner_result.get('scanner', 'unknown')
        results = scanner_result.get('results', [])

        self.logger.debug(f"Merging {len(results)} results from {scanner_name}")

        # Store scanner-specific results in metadata
        if 'scanner_results' not in self.results.metadata:
            self.results.metadata['scanner_results'] = {}

        self.results.metadata['scanner_results'][scanner_name] = scanner_result

    def _post_process_results(self):
        """Post-process and enrich results."""
        self.logger.info("Post-processing results")

        # Aggregate data from scanner results
        scanner_results = self.results.metadata.get('scanner_results', {})

        # Collect hosts
        for scanner_name, data in scanner_results.items():
            for result in data.get('results', []):
                if 'host' in result:
                    self.results.add_host(result['host'])
                if 'port' in result:
                    self.results.add_port(result['port'])
                if 'service' in result:
                    self.results.add_service(result['service'])
                if 'vulnerability' in result:
                    self.results.add_vulnerability(result['vulnerability'])
                if 'technology' in result:
                    self.results.add_technology(result['technology'])

        # Calculate statistics
        self.results.metadata['statistics'] = {
            'total_hosts': len(self.results.hosts),
            'total_ports': len(self.results.ports),
            'total_services': len(self.results.services),
            'total_vulnerabilities': len(self.results.vulnerabilities),
            'total_technologies': len(self.results.technologies),
        }

    def generate_report(self, output_format: str = 'html', output_file: Optional[str] = None) -> str:
        """
        Generate scan report.

        Args:
            output_format: Report format (html, json, pdf, csv)
            output_file: Output file path

        Returns:
            Report content or file path
        """
        from ..reporting.report_generator import ReportGenerator

        generator = ReportGenerator(self.config)
        return generator.generate(self.results, output_format, output_file)

    def export_json(self, output_file: str):
        """Export results to JSON file."""
        import json
        from pathlib import Path

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(self.results.to_dict(), f, indent=2)

        self.logger.info(f"Results exported to {output_file}")
