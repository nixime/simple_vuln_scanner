import json
import requests


class KEV:
    __base_kev_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    __kev_list = []
    __verify_certificate = True
    
    def __init__(self, verify_certificate=True):
        self.__verify_certificate = verify_certificate

    def __query_json(self):
        """
        A private method used to send a GET request to the NVD API

        Args:
            url (str): CISA KEV JSON file

        Returns:
            dict: Parsed JSON data if the request is successful (HTTP 200).
            None: If the request fails or returns a non-200 status code.
        """
        url = f"{self.__base_kev_url}"
        response = requests.get(url, verify=self.__verify_certificate)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print(f"query: {url}")
            print(response)
            return None

    def load_kevs(self):
        """
        Method to load the KEV database
        """
        json_obj = self.__query_json( )
        for vuln in json_obj['vulnerabilities']:
            self.__kev_list.append(vuln['cveID'])


    def query_cpe(self, cve_id):
        return( cve_id in self.__kev_list )


    