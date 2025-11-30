from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Dependency:
    name: str
    version: str
    type: str
    purl: Optional[str] = None

    @property
    def derived_vendor(self) -> Optional[str]:
        if not self.purl:
            return None
        try:
            # Basic PURL parsing: pkg:type/namespace/name@version
            if "pkg:" not in self.purl:
                return None
            # Remove scheme
            rest = self.purl.split(":", 1)[1]
            # Split type and rest (e.g. maven/org.springframework/spring-core@...)
            if "/" not in rest:
                return None
            
            # Find the name part (last segment before @)
            # But wait, namespace can contain slashes?
            # Usually: type/namespace/name
            # If no namespace: type/name
            
            # Let's strip version first
            path = rest.split("@")[0]
            
            # Now path is type/namespace/name or type/name
            parts = path.split("/")
            if len(parts) < 3:
                return None
            
            # Namespace is everything between type and name
            namespace = "/".join(parts[1:-1])
            
            import urllib.parse
            decoded = urllib.parse.unquote(namespace)
            return decoded.replace("@", "")
        except Exception:
            return None

@dataclass
class Vulnerability:
    cve_id: str
    description: Optional[str] = None
    cvss_v31_score: Optional[float] = None
    cvss_v31_severity: Optional[str] = None
    cvss_v40_score: Optional[float] = None
    cvss_v40_severity: Optional[str] = None

@dataclass
class ScanResult:
    dependency: Dependency
    vulnerabilities: List[Vulnerability]
    vendor: Optional[str] = None
