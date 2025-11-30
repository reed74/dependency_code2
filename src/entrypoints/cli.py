import argparse
import sys
import os
import json
import dataclasses

# Add project root to sys.path so we can import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from dotenv import load_dotenv
load_dotenv()

from src.adapters.scanner.syft_scanner import SyftScanner
from src.adapters.db.postgres_repo import PostgresRepository
from src.adapters.scm.git_provider import GitProvider
from src.application.service import DependencyAnalysisService

class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)

def main():
    parser = argparse.ArgumentParser(description="Analyze dependencies for vulnerabilities.")
    parser.add_argument("--path", help="Path to the directory to scan")
    parser.add_argument("--repo-url", help="URL of the git repository to scan")
    parser.add_argument("--output", help="Path to save the JSON output", required=True)
    args = parser.parse_args()

    if not args.path and not args.repo_url:
        print("Error: Either --path or --repo-url must be provided.")
        sys.exit(1)

    try:
        scanner = SyftScanner()
        repo = PostgresRepository()
        scm = GitProvider()
        service = DependencyAnalysisService(scanner, repo, scm)
        
        print("Starting analysis...")
        results = service.analyze(path=args.path, url=args.repo_url)
        
        # Save to JSON
        with open(args.output, 'w') as f:
            json.dump(results, f, cls=EnhancedJSONEncoder, indent=2)
        
        print(f"Analysis complete. Results saved to {args.output}")
        print(f"Found {len(results)} dependencies.")
        
        vuln_count = sum(1 for r in results if r.vulnerabilities)
        print(f"Dependencies with vulnerabilities: {vuln_count}")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
