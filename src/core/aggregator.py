class VulnerabilityAggregator:
    """
    Orchestrates vulnerability lookups across multiple security data sources.
    
    This class acts as a router, directing queries to the appropriate API 
    (NVD, OSV, or Dependency-Track) based on the format of the provided 
    identifier (CPE vs PURL).
    """

    def __init__(self, source_locations, config, val_cert, score_ver):
        """
        Initializes sources based on the source_locations string.
        
        Args:
            source_locations (str): Comma-separated list of sources (e.g., 'nvd,osv').
            config: Configuration object containing API keys and rate limits.
            val_cert: SSL certificate validation setting.
            score_ver: The preferred CVSS version for scoring.
        """
        self.sources = {}
        # Clean and normalize input source names
        self.locations = [s.strip().lower() for s in source_locations.split(',')]
        self.verbose_logging = getattr(config.GLOBAL, "verbose_logging", True)
        
        # Priority Logic: If Dependency-Track is requested, it overrides other sources.
        # This "Strict" mode ensures data consistency from a single internal source.
        if "dependency_track" in self.locations:
            import core.dependency_track as dt
            self.sources["dt"] = dt.DependencyTrack(config.DT.url, config.DT.key, score_ver, val_cert, self.verbose_logging)
        else:
            # Initialize NVD if present in locations
            if "nvd" in self.locations:
                limit = config.NVD.requests_per_delay
                delay = config.NVD.request_delay
                from core.nvd import NVD
                self.sources["nvd"] = NVD(
                    config.NVD.api_key, val_cert, score_ver, limit, delay, self.verbose_logging
                )
            
            # Initialize Google OSV if present in locations
            if "osv" in self.locations:
                from core.osv import OSV
                # OSV is hardcoded to a batch size of 20 as per internal requirements
                self.sources["osv"] = OSV(20, val_cert, self.verbose_logging)

    def process_individual_cpes(self):
        if "dependency_track" in self.locations:
            return False
        return True

    def get_vulnerabilities(self, identifier):
        """
        Queries all active sources for a specific component identifier.
        
        The method filters sources by identifier type:
        - NVD: Only accepts CPE strings (cpe:).
        - OSV: Only accepts Package URLs (pkg:).

        Args:
            identifier (str): The CPE or PURL of the component to check.

        Returns:
            list: A list of standardized vulnerability dictionaries.
        """
        results = []

        if self.verbose_logging:
            print(f"    [*] Querying for vulnerabilities ({identifier})")

        for name, source in self.sources.items():
            # Source Routing: Prevent invalid API calls by checking identifier prefixes
            if name == "nvd" and not identifier.startswith("cpe:"):
                continue
            if name == "osv" and not identifier.startswith("pkg:"):
                continue

            # Execute the query against the specific source implementation
            data = source.query_for_vulnerabilities(identifier)
            
            # Defensive check: Ensure data is a valid dictionary payload before continuing
            if not isinstance(data, dict):
                continue

            # Extract the list of vulnerabilities (keys differ between NVD and OSV/DT)
            vulns = data.get('vulnerabilities', data.get('vulns', []))
            
            for v in vulns:
                # Defensive check for NVD: tokenize_vuln explicitly expects a dictionary 
                # containing a 'cve' key. Skip malformed objects to prevent KeyErrors.
                if name == "nvd" and (not isinstance(v, dict) or 'cve' not in v):
                    continue

                # Standardize the raw JSON into a common format using the source's tokenizer
                results.append(source.tokenize_vuln(v))
                
        return results