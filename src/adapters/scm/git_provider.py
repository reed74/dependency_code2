import subprocess
import tempfile
import shutil
import os
from src.domain.ports import SourceCodeProvider

class GitProvider(SourceCodeProvider):
    def clone(self, url: str) -> str:
        if not shutil.which("git"):
            raise RuntimeError("git is not installed or not in PATH")

        temp_dir = tempfile.mkdtemp(prefix="dependency-analysis-")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, temp_dir],
                check=True,
                capture_output=True,
                text=True
            )
            return temp_dir
        except subprocess.CalledProcessError as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed: {e.stderr}")

    def cleanup(self, path: str):
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
