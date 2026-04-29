import unittest
from unittest.mock import patch, MagicMock
from core.osv import OSV

class TestOSV(unittest.TestCase):
    def setUp(self):
        """
        Initializes a 'clean' instance of the OSV class before every test.
        This ensures that state (like request counters) doesn't leak between tests.
        """
        self.osv_client = OSV(timeout=5, validate_cert=True, verbose_logging=False)

    @patch('requests.post')
    def test_alias_resolution_logic(self, mock_post):
        """
        SCENARIO: 
        We query OSV for 'requests@2.25.1'. The OSV API returns a 'GHSA' ID, 
        but it contains a 'CVE-2023-XXXX' in its aliases list.

        WHY WE TEST THIS:
        Your report depends on CVE IDs to fetch EPSS scores and KEV status. 
        If OSV only returns a GitHub Advisory ID (GHSA), the rest of your 
        scanner's enrichment logic will break.
        """

        # --- 1. THE MOCK (What the internet 'returns') ---
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-pw3v-636v-6pqq", # Internal OSV ID
                    "aliases": ["CVE-2023-32681"], # The "True" ID we need
                    "summary": "Information Exposure in requests",
                    "database_specific": {"severity": "HIGH"},
                    "severity": [{
                        "type": "CVSS_V3", 
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                    }]
                }
            ]
        }
        mock_post.return_value = mock_response

        # --- 2. THE EXECUTION (The action we are testing) ---
        # We simulate querying for a specific Python package
        raw_data = self.osv_client.query_for_vulnerabilities("pkg:pypi/requests@2.25.1")
        
        # We take the first vulnerability found and 'tokenize' it 
        # (This runs your custom logic in osv.py)
        tokenized_result = self.osv_client.tokenize_vuln(raw_data['vulns'][0])

        # --- 3. THE EXPECTATIONS (What MUST be true for the test to pass) ---
        
        # EXPECTATION A: The 'id' field should remain the primary OSV ID.
        self.assertEqual(tokenized_result['id'], "GHSA-pw3v-636v-6pqq")

        # EXPECTATION B: The 'cve_id' field must be extracted from the 'aliases'.
        # This is the most critical part of your OSV logic!
        self.assertEqual(tokenized_result['cve_id'], "CVE-2023-32681")

        # EXPECTATION D: Payload structure.
        # Verify the code actually sent the PURL to the OSV API correctly.
        sent_payload = mock_post.call_args[1]['json']
        self.assertEqual(sent_payload['package']['purl'], "pkg:pypi/requests@2.25.1")

    @patch('requests.post')
    def test_empty_response_handling(self, mock_post):
        """
        SCENARIO: 
        OSV returns an empty JSON object because the package is safe.

        EXPECTED RESULT: 
        The method should return an empty dictionary '{}' without crashing.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {} 
        mock_post.return_value = mock_response

        result = self.osv_client.query_for_vulnerabilities("pkg:pypi/safe-lib@1.0")
        
        # Verify it gracefully returns an empty dict
        self.assertEqual(result, {})

if __name__ == '__main__':
    unittest.main()