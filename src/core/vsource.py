from abc import ABC, abstractmethod

class VulnerabilitySource(ABC):
    def __init__(self, validate_cert=True, verbose_logging=False):
        self.validate_certificate = validate_cert
        self.verbose_logging = verbose_logging

    @abstractmethod
    def query_for_vulnerabilities(self, identifier: str) -> dict:
        """Fetch raw data from the API."""
        pass

    @abstractmethod
    def tokenize_vuln(self, raw_json: dict) -> dict:
        """Standardize raw JSON into a common dictionary format."""
        pass