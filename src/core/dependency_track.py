import requests
import urllib.parse
from core.vsource import VulnerabilitySource

class DependencyTrack(VulnerabilitySource):
    
    """
    Client for a local Dependency-Track instance.
    """
    def __init__(self, api_url, api_key, verify_certificate=True, verbose_logging=True):
        super().__init__(verify_certificate, verbose_logging)
        self.__base_url = api_url.rstrip('/')
        self.__api_key = api_key        

    def __get_headers(self):
        return {
            "X-Api-Key": self.__api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def query_for_vulnerabilities(self, cpe):
        """
        Retrieves all vulnerability findings from DT's internal database 
        based on a specific CPE string.
        """
        # 1. URL encode the CPE string to handle colons and slashes safely
        encoded_cpe = urllib.parse.quote_plus(cpe)
        url = f"{self.__base_url}/api/v1/vulnerability/component?cpe={encoded_cpe}"
        
        try:
            response = requests.get(
                url, 
                headers=self.__get_headers(), 
                verify=self.validate_certificate
            )
            
            if response.status_code == 200:
                # 2. DT returns a list [ {...}, {...} ]. 
                # Wrap it in a dict so aggregator.py can process it consistently.
                return {"vulnerabilities": response.json()}
            
            elif response.status_code == 404:
                # CPE not found in DT's mirror; return empty list, not an error
                return {"vulnerabilities": []}
                
            return {}
            
        except Exception as e:
            if self.verbose_logging:
                print(f"[-] DT Connection Error for {cpe}: {e}")
            return {}

    def tokenize_vuln(self, finding_json):
        """
        Flattens DT finding format into your standardized dictionary.
        """
        vulnerability = finding_json.get('vulnerability', {})
        cvss_version = vulnerability.get('cvssVersion')
        
        return {
            "id": vulnerability.get('vulnId'),
            "cve_id": vulnerability.get('vulnId'),
            "published": vulnerability.get('published'),
            "description": vulnerability.get('description'),
            "status": "ANALYZED", # DT findings are usually pre-processed
            "base_score": vulnerability.get('cvssScore', 0.0),
            "vector": vulnerability.get('cvssVector', "N/A"),
            "version": cvss_version
        }