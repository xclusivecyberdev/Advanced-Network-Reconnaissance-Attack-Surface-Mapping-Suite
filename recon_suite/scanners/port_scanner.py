"""Port scanning module using Scapy and python-nmap."""

import nmap
from scapy.all import *
from typing import Dict, Any, List, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from ..core.scanner_base import BaseScanner
from ..utils.validators import validate_ip, validate_cidr
from ..utils.network_utils import expand_cidr


class PortScanner(BaseScanner):
    """Advanced port scanner using multiple techniques."""

    def __init__(self, config):
        """Initialize port scanner."""
        super().__init__(name="PortScanner", version="1.0", config=config)
        self.nm = nmap.PortScanner()

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform port scan on target.

        Args:
            target: Target IP or CIDR
            options: Scan options (ports, scan_type, timing, etc.)

        Returns:
            Scan results
        """
        options = options or {}
        ports = options.get('ports', '1-1000')
        scan_type = options.get('scan_type', 'syn')
        timing = options.get('timing', 'normal')

        # Expand CIDR if needed
        targets = self._expand_targets(target)

        # Perform scans based on type
        if scan_type == 'nmap':
            return self._nmap_scan(targets, ports, timing)
        elif scan_type == 'syn':
            return self._syn_scan(targets, ports)
        elif scan_type == 'ack':
            return self._ack_scan(targets, ports)
        elif scan_type == 'udp':
            return self._udp_scan(targets, ports)
        elif scan_type == 'comprehensive':
            return self._comprehensive_scan(targets, ports)
        else:
            return self._nmap_scan(targets, ports, timing)

    def _expand_targets(self, target: str) -> List[str]:
        """Expand target to list of IPs."""
        if validate_cidr(target):
            return expand_cidr(target, max_hosts=256)
        elif validate_ip(target):
            return [target]
        else:
            # Try to resolve hostname
            from ..utils.network_utils import get_ip_from_hostname
            ip = get_ip_from_hostname(target)
            return [ip] if ip else []

    def _nmap_scan(self, targets: List[str], ports: str, timing: str = 'normal') -> Dict[str, Any]:
        """
        Perform nmap scan.

        Args:
            targets: List of target IPs
            ports: Port specification
            timing: Timing template

        Returns:
            Scan results
        """
        results = []

        # Timing templates
        timing_map = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5',
        }

        timing_arg = timing_map.get(timing, '-T3')

        for target in targets:
            try:
                self.logger.info(f"Nmap scanning {target} on ports {ports}")

                # Build nmap arguments
                arguments = f'{timing_arg} -sV -sC'

                # Perform scan
                self.nm.scan(hosts=target, ports=ports, arguments=arguments)

                # Parse results
                for host in self.nm.all_hosts():
                    host_info = {
                        'host': host,
                        'hostname': self.nm[host].hostname(),
                        'state': self.nm[host].state(),
                        'ports': [],
                    }

                    for proto in self.nm[host].all_protocols():
                        ports_list = self.nm[host][proto].keys()

                        for port in ports_list:
                            port_info = {
                                'port': port,
                                'protocol': proto,
                                'state': self.nm[host][proto][port]['state'],
                                'service': self.nm[host][proto][port].get('name', ''),
                                'version': self.nm[host][proto][port].get('version', ''),
                                'product': self.nm[host][proto][port].get('product', ''),
                                'extrainfo': self.nm[host][proto][port].get('extrainfo', ''),
                            }
                            host_info['ports'].append(port_info)

                    self.add_result({'host': host_info})
                    results.append(host_info)

            except Exception as e:
                self.add_error(f"Nmap scan failed for {target}: {e}")

        return {'scanner': self.name, 'results': results}

    def _syn_scan(self, targets: List[str], ports: str) -> Dict[str, Any]:
        """
        Perform SYN scan using Scapy.

        Args:
            targets: List of target IPs
            ports: Port specification

        Returns:
            Scan results
        """
        results = []
        port_list = self._parse_ports(ports)

        conf.verb = 0  # Suppress Scapy output

        for target in targets:
            try:
                self.logger.info(f"SYN scanning {target}")

                open_ports = []

                for port in port_list:
                    # Create SYN packet
                    syn_packet = IP(dst=target) / TCP(dport=port, flags='S')

                    # Send packet and wait for response
                    response = sr1(syn_packet, timeout=1, verbose=0)

                    if response and response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                            # Port is open, send RST to close connection
                            rst_packet = IP(dst=target) / TCP(dport=port, flags='R')
                            send(rst_packet, verbose=0)

                            open_ports.append({
                                'port': port,
                                'state': 'open',
                                'protocol': 'tcp',
                            })

                    # Rate limiting
                    time.sleep(self.config.get('scanning.rate_limit_delay', 0.1))

                if open_ports:
                    host_info = {
                        'host': target,
                        'state': 'up',
                        'ports': open_ports,
                    }
                    self.add_result({'host': host_info})
                    results.append(host_info)

            except Exception as e:
                self.add_error(f"SYN scan failed for {target}: {e}")

        return {'scanner': self.name, 'scan_type': 'syn', 'results': results}

    def _ack_scan(self, targets: List[str], ports: str) -> Dict[str, Any]:
        """
        Perform ACK scan using Scapy (firewall detection).

        Args:
            targets: List of target IPs
            ports: Port specification

        Returns:
            Scan results
        """
        results = []
        port_list = self._parse_ports(ports)

        conf.verb = 0

        for target in targets:
            try:
                self.logger.info(f"ACK scanning {target}")

                filtered_ports = []
                unfiltered_ports = []

                for port in port_list:
                    # Create ACK packet
                    ack_packet = IP(dst=target) / TCP(dport=port, flags='A')

                    # Send packet and wait for response
                    response = sr1(ack_packet, timeout=1, verbose=0)

                    if response is None:
                        filtered_ports.append(port)
                    elif response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x04:  # RST
                            unfiltered_ports.append(port)

                    time.sleep(self.config.get('scanning.rate_limit_delay', 0.1))

                host_info = {
                    'host': target,
                    'filtered_ports': filtered_ports,
                    'unfiltered_ports': unfiltered_ports,
                    'firewall_detected': len(filtered_ports) > 0,
                }

                self.add_result({'host': host_info})
                results.append(host_info)

            except Exception as e:
                self.add_error(f"ACK scan failed for {target}: {e}")

        return {'scanner': self.name, 'scan_type': 'ack', 'results': results}

    def _udp_scan(self, targets: List[str], ports: str) -> Dict[str, Any]:
        """
        Perform UDP scan using Scapy.

        Args:
            targets: List of target IPs
            ports: Port specification

        Returns:
            Scan results
        """
        results = []
        # Common UDP ports
        common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900]
        port_list = common_udp_ports if ports == '1-1000' else self._parse_ports(ports)

        conf.verb = 0

        for target in targets:
            try:
                self.logger.info(f"UDP scanning {target}")

                open_ports = []

                for port in port_list:
                    # Create UDP packet
                    udp_packet = IP(dst=target) / UDP(dport=port)

                    # Send packet and wait for response
                    response = sr1(udp_packet, timeout=2, verbose=0)

                    if response is None:
                        # No response might mean open|filtered
                        open_ports.append({
                            'port': port,
                            'state': 'open|filtered',
                            'protocol': 'udp',
                        })
                    elif response.haslayer(ICMP):
                        icmp_type = response.getlayer(ICMP).type
                        if icmp_type == 3:  # Destination unreachable
                            pass  # Port is closed
                    elif response.haslayer(UDP):
                        # Got UDP response, port is open
                        open_ports.append({
                            'port': port,
                            'state': 'open',
                            'protocol': 'udp',
                        })

                    time.sleep(self.config.get('scanning.rate_limit_delay', 0.2))

                if open_ports:
                    host_info = {
                        'host': target,
                        'state': 'up',
                        'ports': open_ports,
                    }
                    self.add_result({'host': host_info})
                    results.append(host_info)

            except Exception as e:
                self.add_error(f"UDP scan failed for {target}: {e}")

        return {'scanner': self.name, 'scan_type': 'udp', 'results': results}

    def _comprehensive_scan(self, targets: List[str], ports: str) -> Dict[str, Any]:
        """
        Perform comprehensive scan (SYN + UDP + Service Detection).

        Args:
            targets: List of target IPs
            ports: Port specification

        Returns:
            Combined scan results
        """
        results = []

        # First do SYN scan
        syn_results = self._syn_scan(targets, ports)

        # Then do UDP scan on common ports
        udp_results = self._udp_scan(targets, '53,161,162,500')

        # Combine results
        results.extend(syn_results.get('results', []))
        results.extend(udp_results.get('results', []))

        return {'scanner': self.name, 'scan_type': 'comprehensive', 'results': results}

    def _parse_ports(self, port_spec: str) -> List[int]:
        """
        Parse port specification.

        Args:
            port_spec: Port specification (e.g., '1-1000', '80,443')

        Returns:
            List of port numbers
        """
        ports = []

        # Handle ranges
        if '-' in port_spec:
            try:
                start, end = port_spec.split('-')
                ports = list(range(int(start), int(end) + 1))
            except ValueError:
                self.logger.error(f"Invalid port range: {port_spec}")
                return [80, 443]  # Default ports

        # Handle comma-separated list
        elif ',' in port_spec:
            try:
                ports = [int(p.strip()) for p in port_spec.split(',')]
            except ValueError:
                self.logger.error(f"Invalid port list: {port_spec}")
                return [80, 443]

        # Single port
        else:
            try:
                ports = [int(port_spec)]
            except ValueError:
                self.logger.error(f"Invalid port: {port_spec}")
                return [80, 443]

        # Limit to valid port range
        ports = [p for p in ports if 1 <= p <= 65535]

        # Limit number of ports to scan (prevent excessive scanning)
        max_ports = 1000
        if len(ports) > max_ports:
            self.logger.warning(f"Too many ports ({len(ports)}), limiting to {max_ports}")
            ports = ports[:max_ports]

        return ports
