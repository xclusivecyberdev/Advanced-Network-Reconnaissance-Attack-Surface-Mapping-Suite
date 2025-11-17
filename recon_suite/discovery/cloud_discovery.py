"""Cloud asset discovery for AWS, Azure, and GCP."""

import requests
import dns.resolver
from typing import Dict, Any, List, Optional
import logging
import re

from ..core.scanner_base import BaseScanner


class CloudAssetDiscovery(BaseScanner):
    """Cloud asset discovery scanner."""

    def __init__(self, config):
        """Initialize cloud asset discovery."""
        super().__init__(name="CloudAssetDiscovery", version="1.0", config=config)

        # Cloud provider patterns
        self.cloud_patterns = {
            'aws': {
                's3': [r'\.s3\.amazonaws\.com', r'\.s3-[\w-]+\.amazonaws\.com', r's3://'],
                'cloudfront': [r'\.cloudfront\.net'],
                'ec2': [r'ec2-[\d-]+\.(compute|amazonaws)'],
                'elb': [r'\.elb\.amazonaws\.com'],
            },
            'azure': {
                'blob': [r'\.blob\.core\.windows\.net'],
                'websites': [r'\.azurewebsites\.net'],
                'cloudapp': [r'\.cloudapp\.azure\.com'],
            },
            'gcp': {
                'storage': [r'\.storage\.googleapis\.com'],
                'appengine': [r'\.appspot\.com'],
                'cloud_run': [r'\.run\.app'],
            },
        }

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Discover cloud assets for target organization.

        Args:
            target: Target domain or organization name
            options: Scan options

        Returns:
            Cloud asset discovery results
        """
        results = []

        # Discover AWS assets
        aws_assets = self._discover_aws_assets(target)
        results.extend(aws_assets)

        # Discover Azure assets
        azure_assets = self._discover_azure_assets(target)
        results.extend(azure_assets)

        # Discover GCP assets
        gcp_assets = self._discover_gcp_assets(target)
        results.extend(gcp_assets)

        for asset in results:
            self.add_result({'cloud_asset': asset})

        return {'scanner': self.name, 'results': results}

    def _discover_aws_assets(self, target: str) -> List[Dict[str, Any]]:
        """Discover AWS assets."""
        assets = []

        # S3 bucket enumeration
        bucket_names = self._generate_bucket_names(target)

        for bucket_name in bucket_names:
            # Check if bucket exists
            bucket_info = self._check_s3_bucket(bucket_name)
            if bucket_info:
                assets.append(bucket_info)

        return assets

    def _discover_azure_assets(self, target: str) -> List[Dict[str, Any]]:
        """Discover Azure assets."""
        assets = []

        # Generate possible Azure resource names
        base_names = [
            target.replace('.', ''),
            target.split('.')[0] if '.' in target else target,
        ]

        for base_name in base_names:
            # Check blob storage
            blob_url = f"https://{base_name}.blob.core.windows.net"
            if self._check_url_exists(blob_url):
                assets.append({
                    'provider': 'azure',
                    'service': 'blob_storage',
                    'resource': base_name,
                    'url': blob_url,
                })

            # Check Azure websites
            website_url = f"https://{base_name}.azurewebsites.net"
            if self._check_url_exists(website_url):
                assets.append({
                    'provider': 'azure',
                    'service': 'web_app',
                    'resource': base_name,
                    'url': website_url,
                })

        return assets

    def _discover_gcp_assets(self, target: str) -> List[Dict[str, Any]]:
        """Discover GCP assets."""
        assets = []

        # Generate possible GCP resource names
        base_names = [
            target.replace('.', '-'),
            target.split('.')[0] if '.' in target else target,
        ]

        for base_name in base_names:
            # Check App Engine
            appengine_url = f"https://{base_name}.appspot.com"
            if self._check_url_exists(appengine_url):
                assets.append({
                    'provider': 'gcp',
                    'service': 'app_engine',
                    'resource': base_name,
                    'url': appengine_url,
                })

            # Check Cloud Run
            cloudrun_url = f"https://{base_name}.run.app"
            if self._check_url_exists(cloudrun_url):
                assets.append({
                    'provider': 'gcp',
                    'service': 'cloud_run',
                    'resource': base_name,
                    'url': cloudrun_url,
                })

        return assets

    def _generate_bucket_names(self, target: str) -> List[str]:
        """Generate possible S3 bucket names."""
        base = target.replace('.', '-').replace('_', '-')
        domain_parts = target.split('.')

        bucket_names = [
            target,
            base,
            domain_parts[0] if domain_parts else target,
            f"{base}-backup",
            f"{base}-backups",
            f"{base}-data",
            f"{base}-assets",
            f"{base}-logs",
            f"{base}-public",
            f"{base}-private",
            f"{base}-prod",
            f"{base}-dev",
            f"{base}-staging",
        ]

        return bucket_names

    def _check_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Check if S3 bucket exists and is accessible."""
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com"
            response = requests.head(url, timeout=5)

            if response.status_code in [200, 403]:
                # Bucket exists
                is_public = response.status_code == 200

                # Try to list contents
                list_url = f"{url}/"
                list_response = requests.get(list_url, timeout=5)

                can_list = list_response.status_code == 200

                return {
                    'provider': 'aws',
                    'service': 's3',
                    'bucket_name': bucket_name,
                    'url': url,
                    'exists': True,
                    'public': is_public,
                    'listable': can_list,
                    'vulnerability': 'Public S3 Bucket' if is_public or can_list else None,
                }

        except Exception as e:
            self.logger.debug(f"S3 bucket check failed for {bucket_name}: {e}")

        return None

    def _check_url_exists(self, url: str) -> bool:
        """Check if URL exists."""
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return response.status_code in [200, 301, 302, 403]
        except Exception:
            return False
