import requests

class EPSSDataMissingError(Exception):
    """Exception raised when an EPSS lookup is attempted for a CVE not in the local cache."""
    pass

class EPSS:
    """
    Manages bulk retrieval and caching of Exploit Prediction Scoring System (EPSS) data.

    This class uses a two-stage process:
    1. Registration: Collect CVE IDs and their associated Excel indexer IDs.
    2. Batch Query: Fetch scores for all registered CVEs in chunks of 100 to optimize API performance.

    Attributes:
        cve_registry (dict): Maps CVE IDs to their source indexer (e.g., Excel row ID).
        epss_cache (dict): Stores the fetched EPSS scores, percentiles, and metadata.
    """

    __verify_certificate = True

    def __init__(self, verify_certificate = True):
        """Initializes empty registry and cache dictionaries."""
        # Maps CVE ID to Indexer ID: { "CVE-2021-44228": 12 }
        self.cve_registry = {}
        # Stores the actual EPSS results: { "CVE-2021-44228": { ...data... } }
        self.epss_cache = {}
        self.__verify_certificate = verify_certificate

    def register_cve(self, cve_id, indexer_id):
        """
        Adds a CVE to the queue for the next bulk query.

        Args:
            cve_id (str): The CVE identifier (e.g., 'CVE-2021-44228').
            indexer_id (int|str): A reference ID (like an Excel row number) 
                used to map the data back to the UI/Report later.
        """
        self.cve_registry[cve_id.upper().strip()] = indexer_id

    def query(self):
        """
        Fetches EPSS data for all registered CVEs in batches.

        This method iterates through the registry, splits it into batches of 100,
        and populates the `epss_cache` with results from first.org.

        Note:
            Existing cache entries are updated if the same CVE is queried again.
        """
        if not self.cve_registry:
            print("No CVEs registered to query.")
            return

        cve_list = list(self.cve_registry.keys())
        
        # The EPSS API works best with batches of ~100
        batch_size = 100
        for i in range(0, len(cve_list), batch_size):
            batch = cve_list[i:i + batch_size]
            cve_str = ",".join(batch)
            
            url = f"https://api.first.org/data/v1/epss?cve={cve_str}"
            
            try:
                response = requests.get(url, timeout=15, verify=self.__verify_certificate)
                response.raise_for_status()
                data = response.json().get("data", [])
                
                for entry in data:
                    cve_id = entry['cve']
                    self.epss_cache[cve_id] = {
                        "indexer_id": self.cve_registry.get(cve_id),
                        "epss": float(entry['epss']),
                        "percentile": float(entry['percentile']),
                        "date": entry['date']
                    }
            except requests.exceptions.RequestException as e:
                print(f"Request failed for batch starting with {batch[0]}: {e}")

    def lookup(self, cve_id):
        """
        Retrieves cached EPSS data for a specific CVE.

        Args:
            cve_id (str): The CVE ID to look up.

        Returns:
            tuple: (data_dict, indexer_id) 
                - data_dict (dict): Contains 'epss', 'percentile', and 'date'.
                - indexer_id: The ID provided during registration.

        Raises:
            EPSSDataMissingError: If the CVE was never queried or not found in the API.
        """
        clean_id = cve_id.upper().strip()
        if clean_id not in self.epss_cache:
            raise EPSSDataMissingError(
                f"No EPSS data available for {clean_id}. Ensure query() was "
                f"called and the CVE exists in the FIRST.org database."
            )
        
        data = self.epss_cache[clean_id]
        indexer = data.get("indexer_id")
        
        return data, indexer

    def __iter__(self):
        """
        Yields results from the cache for easy iteration.

        Yields:
            tuple: (cve_id, epss_score, indexer_id)
        """
        for cve_id, data in self.epss_cache.items():
            yield cve_id, data['epss'], data.get('indexer_id')