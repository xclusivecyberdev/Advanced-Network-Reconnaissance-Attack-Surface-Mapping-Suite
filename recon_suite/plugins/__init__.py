"""Plugin system for extending functionality."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class ScannerPlugin(ABC):
    """Base class for scanner plugins."""

    def __init__(self, name: str, version: str = "1.0"):
        """Initialize plugin."""
        self.name = name
        self.version = version
        self.enabled = True

    @abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute plugin scan."""
        pass

    def pre_scan(self, target: str) -> bool:
        """Pre-scan hook."""
        return True

    def post_scan(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Post-scan hook."""
        return results


class ReporterPlugin(ABC):
    """Base class for reporter plugins."""

    def __init__(self, name: str, version: str = "1.0"):
        """Initialize plugin."""
        self.name = name
        self.version = version

    @abstractmethod
    def generate(self, data: Dict[str, Any], output_file: str) -> str:
        """Generate report."""
        pass


# Example custom scanner plugin
class ExamplePlugin(ScannerPlugin):
    """Example scanner plugin."""

    def __init__(self):
        super().__init__(name="ExamplePlugin", version="1.0")

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Scan implementation."""
        return {
            'scanner': self.name,
            'results': [
                {'message': f'Example scan of {target}'}
            ]
        }


__all__ = ['ScannerPlugin', 'ReporterPlugin', 'ExamplePlugin']
