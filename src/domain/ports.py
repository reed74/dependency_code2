from typing import List, Tuple, Optional
from abc import ABC, abstractmethod
from .models import Dependency, Vulnerability

class DependencyScanner(ABC):
    @abstractmethod
    def scan(self, path: str) -> List[Dependency]:
        """Scans a directory and returns a list of dependencies."""
        pass

class VulnerabilityRepository(ABC):
    @abstractmethod
    def get_vulnerabilities(self, product: str, version: str) -> Tuple[List[Vulnerability], Optional[str]]:
        """Retrieves vulnerabilities and vendor for a given product and version."""
        pass

class SourceCodeProvider(ABC):
    @abstractmethod
    def clone(self, url: str) -> str:
        """Clones a repository and returns the local path."""
        pass

    @abstractmethod
    def cleanup(self, path: str):
        """Removes the local path."""
        pass
