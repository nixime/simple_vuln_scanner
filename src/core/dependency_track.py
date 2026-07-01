import requests
import urllib.parse
from core.vsource import VulnerabilitySource
from datetime import datetime, timezone

class DependencyTrack(VulnerabilitySource):
    
    """
    Client for a local Dependency-Track instance.
    """
    def __init__(self, api_url, api_key, metric_version="3.1", verify_certificate=True, verbose_logging=True):
        super().__init__(verify_certificate, verbose_logging)
        self.__base_url = api_url.rstrip('/')
        self.__api_key = api_key     
        self.__metric_version = str(metric_version)   

    def __get_headers(self):
        return {
            "X-Api-Key": self.__api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def query_for_vulnerabilities(self, project_id):
        """
        Retrieves all vulnerability findings from DT's internal database.
        Handles pagination, size limits, authorization errors, and bad requests.
        """
        base_url = f"http://{self.__base_url}/api/v1/finding/project/{project_id}"
        
        all_vulnerabilities = []
        page = 1
        size = 100  # Safe max limit for Dependency-Track
        
        try:
            while True:
                url = f"{base_url}?page={page}&size={size}"
                
                response = requests.get(
                    url, 
                    headers=self.__get_headers(), 
                    verify=self.validate_certificate
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if not data:
                        break
                        
                    all_vulnerabilities.extend(data)
                    if len(data) < size:
                        break
                        
                    page += 1
                    
                elif response.status_code == 404:
                    if page == 1:
                        return {"vulnerabilities": []}
                    break 

                elif response.status_code == 400:
                    if self.verbose_logging:
                        print(f"    [-] DT 400 Bad Request: Check if page size ({size}) is too large or UUID is malformed.")
                    return {"vulnerabilities": []}

                elif response.status_code in [401, 403]:
                    if self.verbose_logging:
                        print(f"    [-] DT Auth Error ({response.status_code}): API key is invalid or lacks 'VIEW_VULNERABILITY' permission.")
                    return {"vulnerabilities": []}

                elif response.status_code == 500:
                    if self.verbose_logging:
                        print(f"    [-] DT 500 Server Error: The database timed out or failed to compile findings for project {project_id}.")

                    # Return whatever partial data we got before the crash, if any
                    return {"vulnerabilities": all_vulnerabilities}
                    
                else:
                    #print(f"    [-] DT Unexpected Status Code {response.status_code} for URL: {url}")
                    break
                    
            return {"vulnerabilities": all_vulnerabilities}
            
        except Exception as e:
            if self.verbose_logging:
                print(f"    [-] DT Connection Error for {base_url}, {e}")
            return {"vulnerabilities": all_vulnerabilities} if all_vulnerabilities else {}

    def tokenize_vuln(self, data_block):
        """
        Extracts CVSS data from the NVD metrics block based on version priority.

        This method implements a 'search down' strategy: it looks for the 
        preferred `__metric_version`, and if not found, searches for the 
        next highest available version below that cap.

        Args:
            metrics (dict): The 'metrics' sub-object from the NVD JSON.
            cve_id (str): For error logging purposes.

        Returns:
            tuple: (version_num, base_score, vector_string)
        """
        from helpers.cvss_helper import CVSSHelper
        
        metric_data = None
        nvd_keys_vect = {
            "4.0": "cvssV4Vector",
            "3.1": "cvssV3Vector",
            "3.0": "cvssV3Vector",
            "2.0": "cvssV2Vector"
        }
        nvd_keys_score = {
            "4.0": "cvssV4Score",
            "3.1": "cvssV3BaseScore",
            "3.0": "cvssV3BaseScore",
            "2.0": "cvssV2BaseScore"
        }
        versions_ordered = ["4.0", "3.1", "3.0","2.0"]

        # Determine which versions are acceptable based on the user's cap
        try:
            start_index = versions_ordered.index(self.__metric_version)
            search_priority = versions_ordered[start_index:]
        except ValueError:
            search_priority = versions_ordered

        # Selection Logic
        convert_from = self.__metric_version
        vect_key = nvd_keys_vect[self.__metric_version]
        scor_key = nvd_keys_score[self.__metric_version]
        vulnerability = data_block.get("vulnerability")
        component = data_block.get("component")

        for version in search_priority:
            vect_key = nvd_keys_vect[version]
            scor_key = nvd_keys_score[version]
            if vulnerability.get(f"{vect_key}"):
                convert_from = version
                if version == "3.0": convert_from = "3.1"
                break

        vector_str = vulnerability.get(f"{vect_key}")
        base_score = vulnerability.get(f"{scor_key}")
        epss_score = vulnerability.get("epssScore")

        # Upgrade vector format if we had to settle for a lower version
        if convert_from != self.__metric_version:
            vector_str, version_num = CVSSHelper.upgrade_vector(
                vector_str, convert_from, self.__metric_version
            )

        # Your Dependency-Track millisecond timestamp
        timestamp_ms = vulnerability.get("published")
        # Convert milliseconds to seconds
        timestamp_s = timestamp_ms / 1000.0
        # Convert to a timezone-aware datetime object (UTC) and format to ISO 8601
        iso_format = datetime.fromtimestamp(timestamp_s, tz=timezone.utc).isoformat()

        data_result = {
            "id": vulnerability.get('vulnId'),
            "cve_id": vulnerability.get('vulnId'),
            "published": iso_format,
            "description": vulnerability.get('description'),
            "status": "ANALYZED", # DT findings are usually pre-processed
            "base_score": base_score,
            "vector": vector_str,
            "version": convert_from,
            "epss_score": epss_score
        }

        return data_result
