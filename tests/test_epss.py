import unittest
from unittest.mock import patch, MagicMock
from core.epss import EPSS

class TestEPSS(unittest.TestCase):
    def setUp(self):
        """
        Initializes EPSS with certificate verification disabled for testing.
        Matches the actual signature: __init__(self, verify_certificate = True)
        """
        self.epss = EPSS(verify_certificate=False)

    def test_registration_normalization(self):
        """
        Tests that the class correctly normalizes CVE IDs (uppercase/strip).
        """
        self.epss.register_cve("  cve-2023-1234  ", 10)
        self.assertIn("CVE-2023-1234", self.epss.cve_registry)
        self.assertEqual(self.epss.cve_registry["CVE-2023-1234"], 10)

    @patch('requests.get')
    def test_query_batching_logic(self, mock_get):
        """
        Verifies that the loop correctly chunks 250 CVEs into 3 API calls.
        This tests the batch_size = 100 logic in the query() method.
        """
        # Register 250 CVEs
        for i in range(250):
            self.epss.register_cve(f"CVE-2023-{i:04d}", i)

        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_get.return_value = mock_response

        self.epss.query()

        # The core class logic check: 250 CVEs / 100 batch size = 3 calls
        self.assertEqual(mock_get.call_count, 3)

    def test_lookup_alignment(self):
        """
        Tests that lookup correctly recombines cached data with the original indexer ID.
        """
        # 1. Register a CVE
        self.epss.register_cve("CVE-2023-0001", 5)
        
        # 2. Manually inject data into the private cache to simulate a successful query()
        # Note: We use the private name mangling _EPSS__epss_cache
        self.epss._EPSS__epss_cache["CVE-2023-0001"] = {
            "indexer_id": 5,
            "epss": 0.95,
            "percentile": 0.99,
            "date": "2023-10-27"
        }

        # 3. Test the lookup method
        data, indexer_id = self.epss.lookup("CVE-2023-0001")
        
        self.assertEqual(indexer_id, 5)
        self.assertEqual(data["epss"], 0.95)

    def test_lookup_fallback(self):
        """
        Tests that the class returns "N/A" for unregistered/unfetched CVEs
        instead of raising an error (as per the code logic).
        """
        # Register but don't fetch
        self.epss.register_cve("CVE-XXXX-XXXX", 99)
        
        data, indexer_id = self.epss.lookup("CVE-XXXX-XXXX")
        
        self.assertEqual(data["epss"], "N/A")
        self.assertEqual(indexer_id, 99)

if __name__ == '__main__':
    unittest.main()