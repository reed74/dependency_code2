from typing import List, Optional
from src.domain.models import ScanResult
from src.domain.ports import DependencyScanner, VulnerabilityRepository, SourceCodeProvider

class DependencyAnalysisService:
    def __init__(self, scanner: DependencyScanner, repo: VulnerabilityRepository, scm: Optional[SourceCodeProvider] = None):
        self.scanner = scanner
        self.repo = repo
        self.scm = scm

    def analyze(self, path: Optional[str] = None, url: Optional[str] = None) -> List[ScanResult]:
        if not path and not url:
            raise ValueError("Either path or url must be provided")

        target_path = path
        is_temp = False

        try:
            if url:
                if not self.scm:
                    raise ValueError("SourceCodeProvider not configured but URL provided")
                target_path = self.scm.clone(url)
                is_temp = True
            
            dependencies = self.scanner.scan(target_path)
            results = []
            
            for dep in dependencies:
                vulnerabilities, vendor = self.repo.get_vulnerabilities(dep.name, dep.version)
                
                # Fallback to PURL-derived vendor if DB didn't return one
                if not vendor:
                    vendor = dep.derived_vendor
                
                # Sanitize vendor
                if vendor:
                    vendor = vendor.replace("@", "")

                # Always include the dependency even if no vulnerabilities found, 
                # but the requirement implies we want to attach CVEs to dependencies.
                # We will return all dependencies, with empty list if no vuln.
                results.append(ScanResult(
                    dependency=dep,
                    vulnerabilities=vulnerabilities,
                    vendor=vendor
                ))
                    
            return results
        finally:
            if is_temp and self.scm and target_path:
                self.scm.cleanup(target_path)
