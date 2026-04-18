import requests

class EPSSDataMissingError(Exception):
    """Custom exception raised when a CVE lookup is attempted without data."""
    pass

class EPSS:
    def __init__(self):
        # Maps CVE ID to Indexer ID: { "CVE-2021-44228": "IDX-123" }
        self.cve_registry = {}
        # Stores the actual EPSS results: { "CVE-2021-44228": { ...data... } }
        self.epss_cache = {}

    def register_cve(self, cve_id, indexer_id):
        """Registers a CVE for later bulk querying."""
        self.cve_registry[cve_id.upper().strip()] = indexer_id

    def query(self):
        """
        Fetches EPSS data for all registered CVEs in bulk.
        Updates the local cache with the results.
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
                response = requests.get(url, timeout=15)
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
        Returns the EPSS data for a single CVE.
        Raises EPSSDataMissingError if the CVE is not in the cache.
        """
        clean_id = cve_id.upper().strip()
        if clean_id not in self.epss_cache:
            raise EPSSDataMissingError(f"No EPSS data available for {clean_id}. Either query() wasn't called or the CVE doesn't exist in the EPSS database.")
        
        # Retrieve the components
        data = self.epss_cache[clean_id]
        indexer = self.cve_registry.get(clean_id)
        
        return data, indexer

    def __iter__(self):
        """
        Allows iterating over the results.
        Yields: (cve_id, data_dict, indexer_id)
        """
        for cve_id, data in self.epss_cache.items():
            indexer_id = self.cve_registry.get(cve_id)
            yield cve_id, data['epss'], indexer_id