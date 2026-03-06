import requests
from typing import Dict, List, Optional, Any

class OSV:
    __base_osv_url = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @staticmethod
    def query_osv(purl: str) -> Dict[str, Any]:
        """
        Queries the OSV database for vulnerabilities associated with a specific PURL.
        
        Args:
            purl (str): The Package URL (e.g., 'pkg:pypi/requests@2.25.1')
            
        Returns:
            dict: The JSON response containing vulnerability data or an empty dict.
        """
        payload = {"package": {"purl": purl}}
        
        try:
            response = requests.post(
                OSV.__base_osv_url, 
                json=payload, 
                timeout=20
            )
            
            # OSV returns a 200 OK even if no vulnerabilities are found,
            # but it will return an empty JSON object {}
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error querying OSV for {purl}: {e}")
            return {}

    def get_vulnerability_ids(self, purl: str) -> List[str]:
        """
        A helper method to extract just the CVE/GHSA IDs from a PURL query.
        """
        data = self.query_osv(purl)
        vulns = data.get('vulns', [])
        return [v.get('id') for v in vulns]

    @staticmethod
    def tokenize_vuln(vuln_json: dict) -> dict:

        cve_id = vuln_json.get('id')
        pub_date = vuln_json.get("published", "Unknown")
        cve_desc = vuln_json.get("summary") or vuln_json.get("details", "No description available")
        cve_status = "WITHDRAWN" if "withdrawn" in vuln_json else "PUBLISHED"
        
        base_score = 0.0
        vector_st = "N/A"
        version_num = "N/A"
        
        severity_list = vuln_json.get("severity", [])
        if severity_list:
            sev = severity_list[0]
            vector_st = sev.get("score", "N/A")
        
        return(cve_id, pub_date,cve_desc,cve_status,base_score,vector_st)