import json
import subprocess
import shutil
import os
from typing import List
from src.domain.models import Dependency
from src.domain.ports import DependencyScanner

class SyftScanner(DependencyScanner):
    def scan(self, path: str) -> List[Dependency]:
        if not shutil.which("syft"):
            raise RuntimeError("syft is not installed or not in PATH")

        try:
            # Run syft and get JSON output
            result = subprocess.run(
                ["syft", path, "-o", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            data = json.loads(result.stdout)
            dependencies = []
            
            # Use a dict to track unique dependencies: key -> Dependency
            unique_deps = {}
            
            for artifact in data.get("artifacts", []):
                name = artifact.get("name")
                version = artifact.get("version")
                type_ = artifact.get("type")
                purl = artifact.get("purl")
                
                if name:
                    # Resolve version using raw name (registries might need special chars like @)
                    if not version or version == "unknown":
                        version = self._get_latest_version(name, type_)
                    
                    # Sanitize name (remove @ as requested) for the output object
                    sanitized_name = name.replace("@", "")
                    
                    # Create a unique key
                    key = (sanitized_name, version, type_)
                    
                    if key not in unique_deps:
                        unique_deps[key] = Dependency(
                            name=sanitized_name,
                            version=version,
                            type=type_,
                            purl=purl
                        )
            
            dependencies = list(unique_deps.values())
            
            # Fallback/Augment: Check for requirements.txt manually
            # Syft might skip packages without versions, but we want to detect them.
            req_path = os.path.join(path, "requirements.txt")
            if os.path.exists(req_path):
                with open(req_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        
                        # Basic parsing
                        if "==" in line:
                            parts = line.split("==")
                            name = parts[0].strip()
                            version = parts[1].split("#")[0].strip()
                        else:
                            import re
                            parts = re.split(r'[<>=!]', line)
                            name = parts[0].strip()
                            version = "unknown"

                        # Check if already found by Syft (using sanitized name comparison)
                        sanitized_name = name.replace("@", "")
                        if not any(d.name == sanitized_name for d in dependencies):
                            if version == "unknown":
                                version = self._get_latest_version(name, "python")
                            
                            dependencies.append(Dependency(
                                name=sanitized_name,
                                version=version,
                                type="python"
                            ))

            return dependencies
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Syft scan failed: {e.stderr}")
        except json.JSONDecodeError:
            raise RuntimeError("Failed to parse Syft output")

    def _get_latest_version(self, package_name: str, package_type: str) -> str:
        """Fetches the latest version of a package from the appropriate repository."""
        try:
            import urllib.request
            import json
            
            headers = {"User-Agent": "DependencyAnalysisTool/1.0"}

            def get_json(url):
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    return json.loads(response.read().decode())
            
            # Python (PyPI)
            if package_type in ["python", "pypi"]:
                url = f"https://pypi.org/pypi/{package_name}/json"
                data = get_json(url)
                return data["info"]["version"]
            
            # Java (Maven)
            elif package_type in ["java-archive", "jenkins-plugin", "maven", "pom"]:
                # Expecting group:artifact or just artifact (less reliable)
                if ":" in package_name:
                    group, artifact = package_name.split(":", 1)
                    q = f'g:"{group}" AND a:"{artifact}"'
                else:
                    q = f'a:"{package_name}"'
                
                # Encode spaces/quotes
                import urllib.parse
                q = urllib.parse.quote(q)
                
                url = f"https://search.maven.org/solrsearch/select?q={q}&rows=1&wt=json"
                data = get_json(url)
                if data["response"]["docs"]:
                    doc = data["response"]["docs"][0]
                    # print(f"Debug Maven Doc: {doc}")
                    return doc.get("v", doc.get("latestVersion", "unknown"))

            # PHP (Packagist)
            elif package_type in ["php-composer", "composer"]:
                # Expecting vendor/package
                url = f"https://packagist.org/packages/{package_name}.json"
                data = get_json(url)
                versions = data["package"]["versions"]
                for v in versions:
                    if "dev" not in v and "alpha" not in v and "beta" not in v:
                        return v
                return list(versions.keys())[0]

            # JavaScript/TypeScript (NPM)
            elif package_type in ["npm", "javascript", "typescript"]:
                # Handle scoped packages (e.g., @angular/core) - raw name should have @
                url = f"https://registry.npmjs.org/{package_name}"
                data = get_json(url)
                return data["dist-tags"]["latest"]

            # Golang (Go Proxy)
            elif package_type in ["go", "gomod"]:
                # https://proxy.golang.org/{module}/@v/list
                # Response is text list of versions
                url = f"https://proxy.golang.org/{package_name}/@v/list"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as response:
                    versions_text = response.read().decode()
                    versions = versions_text.strip().split("\n")
                    # Return last one (usually latest)
                    if versions:
                        return versions[-1]

            # .NET (NuGet)
            elif package_type in ["dotnet", "nuget"]:
                # https://api.nuget.org/v3-flatcontainer/{id}/index.json
                url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/index.json"
                data = get_json(url)
                versions = data.get("versions", [])
                if versions:
                    return versions[-1]

            return "unknown"
        except Exception as e:
            print(f"Debug Error: {e}")
            return "unknown"
