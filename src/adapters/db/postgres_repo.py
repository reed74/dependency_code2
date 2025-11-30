import os
from typing import List, Tuple, Optional
from sqlalchemy import create_engine, text, URL
from sqlalchemy.orm import sessionmaker
from src.domain.models import Vulnerability
from src.domain.ports import VulnerabilityRepository

class PostgresRepository(VulnerabilityRepository):
    def __init__(self, connection_string: str = None):
        if connection_string is None:
            # Fallback to env vars or default
            user = os.getenv("DB_USER", "postgres")
            password = os.getenv("DB_PASSWORD", "postgres")
            host = os.getenv("DB_HOST", "localhost")
            port = os.getenv("DB_PORT", "5432")
            dbname = os.getenv("DB_NAME", "postgres")
            
            # Use URL.create to handle special characters in password safely
            connection_url = URL.create(
                drivername="postgresql+psycopg2",
                username=user,
                password=password,
                host=host,
                port=port,
                database=dbname
            )
            self.engine = create_engine(connection_url)
        else:
            self.engine = create_engine(connection_string)
        
        self.Session = sessionmaker(bind=self.engine)

    def get_vulnerabilities(self, product_name: str, version: str) -> Tuple[List[Vulnerability], Optional[str]]:
        session = self.Session()
        try:
            # 1. Check for alias
            alias_query = text("SELECT canonical_name FROM package_aliases WHERE alias_name = :name")
            alias_result = session.execute(alias_query, {"name": product_name}).fetchone()
            
            search_name = product_name
            if alias_result:
                search_name = alias_result.canonical_name
            
            # 2. If search_name contains '/', try to split it and use the last part
            # This handles scoped packages like @angular/core or maven group/artifact
            # The user confirmed DB products don't have slashes.
            potential_names = [search_name]
            if "/" in search_name:
                potential_names.append(search_name.split("/")[-1])
            
            # We need to loop through potential names until we find a match or run out
            vulnerabilities = []
            vendor = None
            
            for name in potential_names:
                query = text("""
                    SELECT 
                        v.cve_id, 
                        v.description, 
                        v.cvss_v31_score, 
                        v.cvss_v31_severity,
                        v.cvss_v40_score, 
                        v.cvss_v40_severity,
                        p.vendor
                    FROM vulnerabilities v
                    JOIN vulnerability_product_map vpm ON v.id = vpm.vulnerability_id
                    JOIN products p ON vpm.product_id = p.id
                    WHERE p.product = :product_name 
                      AND p.version = :version
                """)
                
                result = session.execute(query, {"product_name": name, "version": version})
                rows = result.fetchall()
                
                if rows:
                    for row in rows:
                        if vendor is None:
                            vendor = row.vendor
                        
                        vulnerabilities.append(Vulnerability(
                            cve_id=row.cve_id,
                            description=row.description,
                            cvss_v31_score=row.cvss_v31_score,
                            cvss_v31_severity=row.cvss_v31_severity,
                            cvss_v40_score=row.cvss_v40_score,
                            cvss_v40_severity=row.cvss_v40_severity
                        ))
                    # If we found something, stop searching
                    break
            
            # If no vulnerabilities found, we might still want to find the vendor if the product exists
            if not vulnerabilities and vendor is None:
                 # Try all potential names for vendor lookup
                 for name in potential_names:
                     prod_query = text("SELECT vendor FROM products WHERE product = :name AND version = :version LIMIT 1")
                     prod_res = session.execute(prod_query, {"name": name, "version": version}).fetchone()
                     if prod_res:
                         vendor = prod_res.vendor
                         break
                
                
            return vulnerabilities, vendor
        finally:
            session.close()
