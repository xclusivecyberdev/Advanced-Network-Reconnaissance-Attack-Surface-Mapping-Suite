"""Technology detection using HTTP headers, favicon hashing, and signatures."""

import requests
import hashlib
import re
from typing import Dict, Any, List, Optional
import logging
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from ..core.scanner_base import BaseScanner


class TechnologyDetector(BaseScanner):
    """Technology and framework detection scanner."""

    def __init__(self, config):
        """Initialize technology detector."""
        super().__init__(name="TechnologyDetector", version="1.0", config=config)

        # Technology signatures (Wappalyzer-style)
        self.signatures = self._load_signatures()

        # Known favicon hashes
        self.favicon_hashes = self._load_favicon_hashes()

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Detect technologies used by target website.

        Args:
            target: Target URL or domain
            options: Scan options

        Returns:
            Technology detection results
        """
        results = []

        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'

        try:
            # Get web page
            response = self._fetch_url(target)

            if response:
                # Detect technologies from different sources
                techs = []

                # HTTP headers
                techs.extend(self._detect_from_headers(response.headers))

                # HTML content
                techs.extend(self._detect_from_html(response.text))

                # Meta tags
                techs.extend(self._detect_from_meta_tags(response.text))

                # JavaScript libraries
                techs.extend(self._detect_javascript_libraries(response.text))

                # Favicon hash
                favicon_tech = self._detect_from_favicon(target)
                if favicon_tech:
                    techs.append(favicon_tech)

                # CMS detection
                cms = self._detect_cms(response.text, response.headers)
                if cms:
                    techs.append(cms)

                # Framework detection
                framework = self._detect_framework(response.text, response.headers)
                if framework:
                    techs.append(framework)

                # Remove duplicates
                unique_techs = self._deduplicate_technologies(techs)

                for tech in unique_techs:
                    self.add_result({'technology': tech})
                    results.append(tech)

        except Exception as e:
            self.add_error(f"Technology detection failed: {e}")

        return {'scanner': self.name, 'results': results}

    def _fetch_url(self, url: str, timeout: int = 10) -> Optional[requests.Response]:
        """Fetch URL content."""
        try:
            headers = {
                'User-Agent': self.config.get('scanning.user_agent',
                                              'Mozilla/5.0 (compatible; ReconSuite/1.0)')
            }

            response = requests.get(url, headers=headers, timeout=timeout,
                                    verify=False, allow_redirects=True)
            return response

        except Exception as e:
            self.logger.error(f"Failed to fetch {url}: {e}")
            return None

    def _detect_from_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect technologies from HTTP headers."""
        technologies = []

        # Server header
        server = headers.get('Server', '')
        if server:
            tech = self._parse_server_header(server)
            if tech:
                technologies.append(tech)

        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append({
                'name': powered_by.split('/')[0],
                'version': powered_by.split('/')[1] if '/' in powered_by else '',
                'category': 'Backend',
                'confidence': 'high',
                'source': 'X-Powered-By header',
            })

        # Framework-specific headers
        framework_headers = {
            'X-AspNet-Version': ('ASP.NET', 'Backend'),
            'X-AspNetMvc-Version': ('ASP.NET MVC', 'Framework'),
            'X-Drupal-Cache': ('Drupal', 'CMS'),
            'X-Generator': ('Generator', 'CMS'),
        }

        for header, (name, category) in framework_headers.items():
            if header in headers:
                technologies.append({
                    'name': name,
                    'version': headers[header],
                    'category': category,
                    'confidence': 'high',
                    'source': f'{header} header',
                })

        return technologies

    def _parse_server_header(self, server: str) -> Optional[Dict[str, Any]]:
        """Parse Server header."""
        # Parse server string (e.g., "Apache/2.4.41 (Ubuntu)")
        parts = server.split()

        if parts:
            name_version = parts[0]
            if '/' in name_version:
                name, version = name_version.split('/', 1)
            else:
                name, version = name_version, ''

            return {
                'name': name,
                'version': version,
                'category': 'Web Server',
                'confidence': 'high',
                'source': 'Server header',
            }

        return None

    def _detect_from_html(self, html: str) -> List[Dict[str, Any]]:
        """Detect technologies from HTML content."""
        technologies = []

        # Parse HTML
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                content = generator.get('content')
                technologies.append({
                    'name': content.split()[0] if content else 'Unknown',
                    'version': '',
                    'category': 'CMS',
                    'confidence': 'high',
                    'source': 'Generator meta tag',
                })

            # WordPress specific
            if 'wp-content' in html or 'wordpress' in html.lower():
                version = self._detect_wordpress_version(html)
                technologies.append({
                    'name': 'WordPress',
                    'version': version,
                    'category': 'CMS',
                    'confidence': 'high',
                    'source': 'HTML patterns',
                })

            # Joomla specific
            if 'joomla' in html.lower() or '/components/com_' in html:
                technologies.append({
                    'name': 'Joomla',
                    'version': '',
                    'category': 'CMS',
                    'confidence': 'high',
                    'source': 'HTML patterns',
                })

            # Drupal specific
            if 'drupal' in html.lower() or '/sites/default/' in html:
                technologies.append({
                    'name': 'Drupal',
                    'version': '',
                    'category': 'CMS',
                    'confidence': 'high',
                    'source': 'HTML patterns',
                })

        except Exception as e:
            self.logger.debug(f"HTML parsing failed: {e}")

        return technologies

    def _detect_from_meta_tags(self, html: str) -> List[Dict[str, Any]]:
        """Detect technologies from meta tags."""
        technologies = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Check all meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')

                if 'generator' in name and content:
                    technologies.append({
                        'name': content,
                        'version': '',
                        'category': 'CMS',
                        'confidence': 'medium',
                        'source': 'Meta tag',
                    })

        except Exception as e:
            self.logger.debug(f"Meta tag detection failed: {e}")

        return technologies

    def _detect_javascript_libraries(self, html: str) -> List[Dict[str, Any]]:
        """Detect JavaScript libraries."""
        technologies = []

        # Common JavaScript library patterns
        js_patterns = {
            'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)', r'jquery\.min\.js'],
            'React': [r'react[.-](\d+\.\d+\.\d+)', r'react\.min\.js'],
            'Angular': [r'angular[.-](\d+\.\d+\.\d+)', r'angular\.min\.js'],
            'Vue.js': [r'vue[.-](\d+\.\d+\.\d+)', r'vue\.min\.js'],
            'Bootstrap': [r'bootstrap[.-](\d+\.\d+\.\d+)', r'bootstrap\.min\.css'],
            'Modernizr': [r'modernizr'],
            'Lodash': [r'lodash'],
        }

        for lib_name, patterns in js_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    version_match = re.search(pattern, html, re.IGNORECASE)
                    version = version_match.group(1) if version_match and version_match.groups() else ''

                    technologies.append({
                        'name': lib_name,
                        'version': version,
                        'category': 'JavaScript Library',
                        'confidence': 'medium',
                        'source': 'Script tags',
                    })
                    break

        return technologies

    def _detect_from_favicon(self, url: str) -> Optional[Dict[str, Any]]:
        """Detect technology from favicon hash."""
        try:
            favicon_url = urljoin(url, '/favicon.ico')
            response = requests.get(favicon_url, timeout=5, verify=False)

            if response.status_code == 200:
                # Calculate hash
                favicon_hash = hashlib.md5(response.content).hexdigest()

                # Check against known hashes
                if favicon_hash in self.favicon_hashes:
                    tech_name = self.favicon_hashes[favicon_hash]
                    return {
                        'name': tech_name,
                        'version': '',
                        'category': 'CMS/Framework',
                        'confidence': 'high',
                        'source': 'Favicon hash',
                        'hash': favicon_hash,
                    }

        except Exception as e:
            self.logger.debug(f"Favicon detection failed: {e}")

        return None

    def _detect_cms(self, html: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Detect Content Management System."""
        # Already covered in HTML detection, but can add more specific checks
        return None

    def _detect_framework(self, html: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Detect web framework."""
        frameworks = {
            'Django': [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
            'Laravel': [r'laravel', r'csrf-token'],
            'Ruby on Rails': [r'rails', r'csrf-param'],
            'Express': [r'X-Powered-By: Express'],
            'Flask': [r'Set-Cookie.*session='],
        }

        for framework_name, patterns in frameworks.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    return {
                        'name': framework_name,
                        'version': '',
                        'category': 'Web Framework',
                        'confidence': 'medium',
                        'source': 'Pattern matching',
                    }

        return None

    def _detect_wordpress_version(self, html: str) -> str:
        """Detect WordPress version."""
        # Look for version in meta tag
        version_match = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', html, re.IGNORECASE)
        if version_match:
            return version_match.group(1)

        # Look for version in generator tag
        gen_match = re.search(r'content="WordPress\s+(\d+\.\d+(?:\.\d+)?)"', html)
        if gen_match:
            return gen_match.group(1)

        return ''

    def _deduplicate_technologies(self, technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate technology detections."""
        unique = {}

        for tech in technologies:
            name = tech['name']
            if name not in unique:
                unique[name] = tech
            else:
                # Keep the one with version if available
                if tech.get('version') and not unique[name].get('version'):
                    unique[name] = tech
                # Keep the one with higher confidence
                elif tech.get('confidence') == 'high':
                    unique[name] = tech

        return list(unique.values())

    def _load_signatures(self) -> Dict[str, Any]:
        """Load technology signatures."""
        # Simplified signature database
        # In production, this would load from a JSON file
        return {}

    def _load_favicon_hashes(self) -> Dict[str, str]:
        """Load known favicon hashes."""
        # Common favicon hashes (simplified)
        return {
            # Add known favicon hashes here
            # 'hash': 'Technology Name'
        }
