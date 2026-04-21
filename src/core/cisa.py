import json
import requests
import urllib3

# Suppress warnings for internal environments with self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class KEV:
    """
    Interface for the CISA Known Exploited Vulnerabilities (KEV) Catalog.

    This class fetches the authoritative list of CVEs known to be exploited 
    in the wild. It allows the application to flag high-risk vulnerabilities 
    during scanning.

    Attributes:
        __base_kev_url (str): The official CISA KEV JSON feed URL.
        __kev_list (list): Cached list of CVE IDs identified as 'known exploited'.
        __verify_certificate (bool): Whether to verify SSL certificates for the request.
    """
    __base_kev_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    __kev_list = []
    __verify_certificate = True
    
    def __init__(self, verify_certificate=True):
        """
        Initializes the KEV handler.

        Args:
            verify_certificate (bool): Set to False if operating behind a 
                corporate proxy that interferes with SSL. Defaults to True.
        """
        self.__verify_certificate = verify_certificate

    def __query_json(self):
        """
        Private method to fetch the latest KEV JSON feed from CISA.

        Returns:
            dict: The parsed JSON response if successful.
            None: If the request fails (logs the status code to console).
        """
        url = self.__base_kev_url
        try:
            response = requests.get(url, verify=self.__verify_certificate)
            if response.status_code == 200:
                return response.json()  # Use built-in .json() helper
            else:
                print(f"KEV Query failed: {url}")
                print(f"Status Code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Connection error fetching KEV: {e}")
            return None

    def load_kevs(self):
        """
        Downloads and parses the KEV catalog, populating the internal cache.

        Note:
            This method should be called once during application startup.
        """
        json_obj = self.__query_json()
        if json_obj and 'vulnerabilities' in json_obj:
            # Using a set for __kev_list would make query_cpe significantly faster
            self.__kev_list = [vuln['cveID'] for vuln in json_obj['vulnerabilities']]

    def query_cpe(self, cve_id):
        """
        Checks if a specific CVE ID exists in the KEV catalog.

        Args:
            cve_id (str): The CVE ID to check (e.g., 'CVE-2023-1234').

        Returns:
            bool: True if the CVE is in the KEV catalog, False otherwise.
        """
        return cve_id in self.__kev_list