import json
import requests
from cvss import CVSS2, CVSS3, CVSS4

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NVD:
    __base_nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    __nvd_api_key = ''
    __verify_certificate = True
    __metric_version = "2.0"

    def __init__(self, key, verify_certificate=True, metric_version="3.1"):
        self.__nvd_api_key = key
        self.__verify_certificate = verify_certificate
        self.__metric_version = str(metric_version)
    
    def __query_api(self, type, id):
        """
        A private method used to send a GET request to the NVD API

        Args:
            url (str): NVD rest API for JSON requests
            key (str): The API key for authentication (passed in headers).
            type (str): The type of request being made to the NVD DB (e.g. cpeName)
            id (str): The CPE string that should be queried from the NVD database

        Returns:
            dict: Parsed JSON data if the request is successful (HTTP 200).
            None: If the request fails or returns a non-200 status code.
        """
        url = f"{self.__base_nvd_url}?{type}={id}"
        headers = {
            'apiKey': self.__nvd_api_key
        }
        response = requests.get(url, headers=headers, verify=self.__verify_certificate)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print(f"query: {url}")
            print(response)
            return None

    def query_for_vulnerabilities(self, cpe_name):
        """
        Method to query the NVD database for CVE details about a single CPE identifier

        Args:
            cpe_name: The CPE string to query (e.g. cpe:2.3:o:linux:linux_kernel:6.19:rc2:*:*:*:*:*:*)
        
        Returns:
            json: raw JSON object provided by the NVD API
            None: If the request fails, then a None object is returned
        """
        return NVD.__query_api(self, 'cpeName', cpe_name)

    def tokenize_metrics_block(self, metrics):
        """
        Static method to tokenize the "metrics" block of a raw NVD JSON object

        Args:
            metrics: Pointer to the metrics block within the raw NVD JSON that needs to be tokenized.
        
        Returns:
            None for any value that is not found, otherwise the following.
            version_num: CVSS Version number used in the Vector String and Base Score
            base_score: Calculated CVSS base score
            vector_str: Vector String containing the details of the CVSS assessment
        """
        metric_data = None
        vector_str = None
        convert_from=2.0

        # Mapping of version strings to NVD JSON keys
        nvd_keys = {
            "4.0": "cvssMetricV40",
            "3.1": "cvssMetricV31",
            "3.0": "cvssMetricV30",
            "2.0": "cvssMetricV2"
        }

        # Define the search order based on the target.
        # We want the highest available version that is <= target_version.
        # If target is 4.0, we check 4.0, then 3.1, then 3.0, then 2.0.
        versions_ordered = ["4.0", "3.1", "3.0", "2.0"]

        try:
            start_index = versions_ordered.index(self.__metric_version)
            search_priority = versions_ordered[start_index:]
        except ValueError:
            search_priority = versions_ordered

        # Get the highest value vector that doesn't go beyond our metric version
        for version in search_priority:
            key = nvd_keys[version]
            if key in metrics:
                metric_data = metrics[key][0]
                convert_from = version
                # Treat 3.0 as 3.1
                if version ==  "3.0":
                    convert_from = "3.1"

        if metric_data is not None:
            cvss_data = metric_data['cvssData']
            vector_str = cvss_data['vectorString']
            base_score = cvss_data['baseScore']

            # We are good to go
            while convert_from != self.__metric_version:
                if convert_from == "2.0":
                    vector_str = NVD.__cvss2_to_cvss3(cvss_data['vectorString'])
                    base_score = CVSS3(vector_str).base_score
                    convert_from = "3.1"

                elif convert_from == "3.1":
                    vector_str = NVD.__cvss3_to_cvss4(cvss_data['vectorString'])
                    base_score = CVSS4(vector_str).base_score
                    convert_from = "4.0"

            version_num = cvss_data['version']

            return(version_num, base_score, vector_str)
        else:
            return(None, None, None)

    def tokenize_cve(self, cve_json):
        cve_id = cve_json['id']
        pub_date = cve_json['published']
        status = cve_json['vulnStatus']

        description = None
        for elem in cve_json['descriptions']:
            if 'en' == elem['lang']:
                description = elem['value']

        if 'metrics' in cve_json:
            (version_num, base_score, vector_str) = self.tokenize_metrics_block(cve_json['metrics'])

        return(cve_id, pub_date, description, status, base_score, vector_str)

    @staticmethod
    def __cvss3_to_cvss4(v31_str):
        # 1. Parse the 3.1 string
        c3 = CVSS3(v31_str)
        
        # User Interaction: 3.1 'R' (Required) -> 4.0 'A' (Active)
        ui_v4 = 'A' if c3.metrics['UI'] == 'R' else 'N'
        
        # Scope: If S:C, move impacts to Subsequent System
        sc, si, sa = (c3.metrics['C'], c3.metrics['I'], c3.metrics['A']) if c3.metrics['S'] == 'C' else ('N', 'N', 'N')

        v4_vector = (
            f"CVSS:4.0/AV:{c3.metrics['AV']}/AC:{c3.metrics['AC']}/AT:N/PR:{c3.metrics['PR']}/UI:{ui_v4}/"
            f"VC:{c3.metrics['C']}/VI:{c3.metrics['I']}/VA:{c3.metrics['A']}/SC:{sc}/SI:{si}/SA:{sa}"
        )
        
        return v4_vector


    @staticmethod
    def __cvss2_to_cvss3(v2_str):
        c2 = CVSS2(v2_str)
        # Access metrics via the .metrics dictionary
        # Typical keys: 'AV', 'AC', 'Au', 'C', 'I', 'A'
        m2 = c2.metrics        
        # Impact Mapping (v2 Partial -> v3 Low, v2 Complete -> v3 High)
        impact_map = {'N': 'N', 'P': 'L', 'C': 'H'}
        # Access Complexity Mapping
        # v2: L, M, H -> v3: L, H
        ac_v3 = 'L' if m2['AC'] == 'L' else 'H'
        # Authentication Mapping
        # v2: N, S, M -> v3 Privileges Required: N, L, H
        pr_v3 = 'N' if m2['Au'] == 'N' else 'L'

        v3_vector = (
            f"CVSS:3.1/AV:{m2['AV']}/AC:{ac_v3}/PR:{pr_v3}/UI:N/S:U/"
            f"C:{impact_map[m2['C']]}/I:{impact_map[m2['I']]}/A:{impact_map[m2['A']]}"
        )
        
        return v3_vector