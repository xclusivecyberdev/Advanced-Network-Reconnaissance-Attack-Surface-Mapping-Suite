"""
Advanced Network Reconnaissance & Attack Surface Mapping Suite

A comprehensive, production-grade network reconnaissance tool for authorized security testing.
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__license__ = "MIT"

from .core.engine import ReconSuite
from .core.config import Config

__all__ = ['ReconSuite', 'Config']


# Legal Banner
LEGAL_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ⚠️  LEGAL DISCLAIMER ⚠️                                ║
║                                                                              ║
║  This tool is designed for AUTHORIZED SECURITY TESTING ONLY.                ║
║                                                                              ║
║  You must have:                                                             ║
║    ✓ Explicit written permission to scan target networks                    ║
║    ✓ Legal authorization for penetration testing activities                 ║
║    ✓ Compliance with all applicable laws and regulations                    ║
║                                                                              ║
║  UNAUTHORIZED USE IS ILLEGAL and may result in:                             ║
║    • Criminal prosecution                                                   ║
║    • Civil liability                                                        ║
║    • Network disruption charges                                             ║
║                                                                              ║
║  The developers assume NO LIABILITY for misuse of this tool.                ║
║                                                                              ║
║  By using this tool, you agree to use it RESPONSIBLY and LEGALLY.           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def print_banner():
    """Print legal disclaimer and tool banner."""
    print(LEGAL_BANNER)
    print(f"\n🔍 Network Reconnaissance Suite v{__version__}")
    print("=" * 80)
