import json
import requests
import urllib3
from core.vsource import VulnerabilitySource

# Suppress warnings for environments with inspection proxies
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NVD(VulnerabilitySource):
    """
    Client for the NIST National Vulnerability Database (NVD) API v2.0.

    This class handles CPE-based vulnerability lookups and implements complex 
    CVSS metric parsing, including version down-selection and vector upgrading.

    Attributes:
        __base_nvd_url (str): The NVD REST API endpoint.
        __nvd_api_key (str): Authentication key to bypass strict rate limits.
        __metric_version (str): The preferred CVSS version (e.g., "3.1").
    """
    __base_nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    __nvd_api_key = ''
    __verify_certificate = True
    __metric_version = "3.1"

    def __init__(self, key, verify_certificate=True, metric_version="3.1"):
        """
        Initializes the NVD client.

        Args:
            key (str): Your NVD API Key.
            verify_certificate (bool): Whether to verify SSL. Defaults to True.
            metric_version (str): The target CVSS version for the report.
        """
        self.__nvd_api_key = key
        self.__verify_certificate = verify_certificate
        self.__metric_version = str(metric_version)
    
    def __query_api(self, query_type, identifier):
        """
        Private method to execute GET requests against the NVD.

        Args:
            query_type (str): The NVD query parameter (e.g., 'cpeName').
            identifier (str): The value to search for (the CPE string).

        Returns:
            dict|None: Parsed JSON data or None if the request failed.
        """
        url = f"{self.__base_nvd_url}?{query_type}={identifier}"
        headers = {'apiKey': self.__nvd_api_key}
        
        try:
            response = requests.get(url, headers=headers, verify=self.__verify_certificate)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"NVD Query Error [{response.status_code}]: {url}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"NVD Connection Error: {e}")
            return None

    def query_for_vulnerabilities(self, cpe_name):
        """
        Queries NVD for all CVEs associated with a specific CPE.

        Args:
            cpe_name (str): The CPE 2.3 string.

        Returns:
            dict: The raw API response containing vulnerability data.
        """
        return self.__query_api('cpeName', cpe_name)

    def tokenize_metrics_block(self, metrics, cve_id="Unknown"):
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
        nvd_keys = {
            "4.0": "cvssMetricV40",
            "3.1": "cvssMetricV31",
            "3.0": "cvssMetricV30",
            "2.0": "cvssMetricV2"
        }
        versions_ordered = ["4.0", "3.1", "3.0", "2.0"]

        # Determine which versions are acceptable based on the user's cap
        try:
            start_index = versions_ordered.index(self.__metric_version)
            search_priority = versions_ordered[start_index:]
        except ValueError:
            search_priority = versions_ordered

        # Selection Logic
        convert_from = self.__metric_version
        for version in search_priority:
            key = nvd_keys[version]
            if key in metrics:
                metric_data = metrics[key][0]
                convert_from = version
                if version == "3.0": convert_from = "3.1"
                break

        if metric_data is None:
            # Catch cases where only a version higher than the cap is available
            if "cvssMetricV40" in metrics and self.__metric_version == "3.1":
                return ("4.0", 0.0, "ERROR: V4_ONLY")
            return (None, None, None)

        cvss_info = metric_data['cvssData']
        vector_str = cvss_info['vectorString']
        version_num = cvss_info['version']

        # Upgrade vector format if we had to settle for a lower version
        if convert_from != self.__metric_version:
            vector_str, version_num = CVSSHelper.upgrade_vector(
                vector_str, convert_from, self.__metric_version
            )
        
        # Calculate score using the centralized helper
        base_score = CVSSHelper.get_score_from_vector(vector_str, version_num)

        return (version_num, base_score, vector_str)

    def tokenize_vuln(self, vuln_json):
        """
        Flattens a single NVD vulnerability entry into a standardized dictionary.

        Args:
            vuln_json (dict): A single 'vulnerability' item from the NVD response.

        Returns:
            dict: Standardized vulnerability data for use in reporting.
        """
        cve_json = vuln_json['cve']
        cve_id = cve_json['id']
        
        # Extract English description
        description = next(
            (d['value'] for d in cve_json['descriptions'] if d['lang'] == 'en'), 
            "No description available."
        )

        version_num, base_score, vector_str = (None, 0.0, "N/A")
        if 'metrics' in cve_json:
            version_num, base_score, vector_str = self.tokenize_metrics_block(
                cve_json['metrics'], cve_id
            )

        return {
            "id": cve_id,
            "cve_id": cve_id,
            "published": cve_json['published'],
            "description": description,
            "status": cve_json['vulnStatus'],
            "base_score": base_score,
            "vector": vector_str,
            "version": version_num
        }