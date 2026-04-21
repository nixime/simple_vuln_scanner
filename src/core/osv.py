import requests
import re
from typing import Dict, List, Optional, Any
from core.vsource import VulnerabilitySource
from helpers.cvss_helper import CVSSHelper

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OSV(VulnerabilitySource):
    __base_osv_url = "https://api.osv.dev/v1/query"
    __validate_certificate = True

    def __init__(self, timeout: int = 10, validate_cert=True):
        self.timeout = timeout
        self.__validate_certificate = validate_cert

    
    def query_for_vulnerabilities(self, purl: str) -> Dict[str, Any]:
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
                self.__base_osv_url, 
                json=payload, 
                timeout=self.timeout,
                verify=self.__validate_certificate
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
        data = self.query_for_vulnerabilities(purl)
        vulns = data.get('vulns', [])
        return [v.get('id') for v in vulns]

    @staticmethod
    def tokenize_vuln(vuln_json: dict, target_version: str = "3.1") -> dict:
        from helpers.cvss_helper import CVSSHelper
        import re

        primary_id = vuln_json.get('id')
        aliases = vuln_json.get('aliases', [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), primary_id)

        pub_date = vuln_json.get("published", "Unknown")
        cve_desc = vuln_json.get("summary") or vuln_json.get("details", "No description available")
        cve_status = "WITHDRAWN" if "withdrawn" in vuln_json else "PUBLISHED"

        base_score = 0.0
        vector_st = "N/A"
        version_num = "N/A"
        
        severity_list = vuln_json.get("severity", [])
        if severity_list:
            all_versions = ["CVSS_V4", "CVSS_V3", "CVSS_V2"]
            
            try:
                # Calculate what we are allowed to look at
                start_idx = all_versions.index(f"CVSS_V{target_version[0]}")
                search_priority = all_versions[start_idx:]
            except (ValueError, IndexError):
                search_priority = all_versions

            target_sev = None
            for ver_key in search_priority:
                target_sev = next((s for s in severity_list if s.get("type") == ver_key), None)
                if target_sev:
                    version_num = "4.0" if ver_key == "CVSS_V4" else ("3.1" if ver_key == "CVSS_V3" else "2.0")
                    break
            
            # --- ERROR HANDLING FOR UNSUPPORTED UPSTREAM VERSIONS ---
            if not target_sev:
                # Check if V4 was the reason we couldn't find a match
                has_v4 = any(s.get("type") == "CVSS_V4" for s in severity_list)
                if has_v4 and target_version == "3.1":
                    print(f"[ERROR] {primary_id}: Only CVSS v4.0 available. Cannot parse/downgrade for 3.1 target.")
                    # Return enough data to be useful, but indicate the error in the vector/score
                    vector_st = "ERROR: V4_ONLY"
                    version_num = "4.0"
                else:
                    # Generic fallback for ecosystem-specific scores (like 'MEDIUM')
                    target_sev = severity_list[0]
                    version_num = "Unknown"
                    vector_st = target_sev.get("score", "N/A")
            else:
                # Standard cleaning and upgrade path
                raw_score_str = target_sev.get("score", "N/A")
                vector_match = re.search(r'(CVSS:[234]\.\d/[^\s]+)', raw_score_str)
                vector_st = vector_match.group(1) if vector_match else raw_score_str

                if version_num in ["2.0", "3.0", "3.1"] and version_num != target_version:
                    vector_st, version_num = CVSSHelper.upgrade_vector(vector_st, version_num, target_version)
                
                base_score = CVSSHelper.get_score_from_vector(vector_st, version_num)

        return {
            "id": primary_id,
            "cve_id": cve_id,
            "published": pub_date,
            "description": cve_desc,
            "status": cve_status,
            "base_score": base_score,
            "vector": vector_st,
            "version": version_num
        }