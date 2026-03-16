import json
from cvss_converter.converter import cvss2_to_cvss3
import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NVD:
    __base_nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    __nvd_api_key = ''
    __verify_certificate = True

    def __init__(self, key, verify_certificate=True):
        self.__nvd_api_key = key
        self.__verify_certificate = verify_certificate
    
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

    @staticmethod
    def tokenize_metrics_block(metrics):
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
        convert_cvss=False

        if 'cvssMetricV30' in metrics:
            metric_data = metrics['cvssMetricV30'][0]
        elif 'cvssMetricV31' in metrics:
            metric_data = metrics['cvssMetricV31'][0]
        elif 'cvssMetricV2' in metrics:
            metric_data = metrics['cvssMetricV2'][0]
            convert_cvss=True

        if metric_data is not None:
            cvss_data = metric_data['cvssData']
            if convert_cvss:
                vector_str, base_score = cvss2_to_cvss3(cvss_data['vectorString'])
            else:
                vector_str = cvss_data['vectorString']
                base_score = cvss_data['baseScore']

            version_num = cvss_data['version']

            return(version_num, base_score, vector_str)
        else:
            return(None, None, None)


    @staticmethod
    def tokenize_cve(cve_json):
        cve_id = cve_json['id']
        pub_date = cve_json['published']
        status = cve_json['vulnStatus']

        description = None
        for elem in cve_json['descriptions']:
            if 'en' == elem['lang']:
                description = elem['value']

        if 'metrics' in cve_json:
            (version_num, base_score, vector_str) = NVD.tokenize_metrics_block(cve_json['metrics'])

        return(cve_id, pub_date, description, status, base_score, vector_str)
    