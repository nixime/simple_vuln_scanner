import unittest
from unittest.mock import patch, MagicMock
from core.nvd import NVD

class TestNVD(unittest.TestCase):
    def setUp(self):
        """
        Initialize NVD with a mock API key and preferred CVSS version.
        """
        # params: key, verify_cert, metric_version, max_req, window, verbose
        self.nvd_client = NVD("mock-api-key", True, "3.1", 50, 30, False)

    @patch('requests.get')
    def test_cvss_priority_and_parsing(self, mock_get):
        """
        SCENARIO:
        NVD returns a CVE that has both CVSS v2.0 and CVSS v3.1 metrics.
        
        EXPECTED RESULT:
        The 'tokenize_vuln' method should prioritize the v3.1 metric 
        as defined in our configuration.
        """
        # 1. Setup Mock Response with mixed metrics
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-1111",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability description"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8
                            }
                        }],
                        "cvssMetricV2": [{
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5
                            }
                        }]
                    },
                    "published": "2023-10-27T15:15:00.000",
                    "lastModified": "2023-10-27T15:15:00.000",
                    "vulnStatus": "Analyzed"
                }
            }]
        }
        mock_get.return_value = mock_response

        # 2. Execute
        raw_data = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:vendor:product:1.0")
        tokenized = self.nvd_client.tokenize_vuln(raw_data['vulnerabilities'][0])

        # 3. Assertions
        # Ensure we picked the 3.1 score (9.8) instead of the 2.0 score (7.5)
        self.assertEqual(tokenized['base_score'], 9.8)
        self.assertEqual(tokenized['version'], "3.1")
        self.assertIn("CVSS:3.1", tokenized['vector'])

    @patch('requests.get')
    def test_upgrade_v2_to_v31(self, mock_get):
        """
        SCENARIO:
        NVD returns a legacy CVE (like CVE-2010-0001) that only contains 
        a CVSS v2.0 metric.

        EXPECTED RESULT:
        The 'tokenize_vuln' method should detect the missing v3.1 metric,
        take the v2.0 vector, and upgrade it to a v3.1 vector before 
        calculating the final base score.
        """
        # 1. Setup Mock Response with ONLY CVSS v2.0
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2010-0001",
                    "descriptions": [{"lang": "en", "value": "Legacy vulnerability description"}],
                    "metrics": {
                        "cvssMetricV2": [{
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5
                            }
                        }]
                    },
                    "published": "2010-01-01T00:00:00.000",
                    "vulnStatus": "Analyzed"
                }
            }]
        }
        mock_get.return_value = mock_response

        # 2. Execute the tokenizer
        raw_data = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:legacy:product:1.0")
        tokenized = self.nvd_client.tokenize_vuln(raw_data['vulnerabilities'][0])

        # 3. Assertions
        # Expectation: The version is now 3.1 (upgraded), not the original 2.0
        self.assertEqual(tokenized['version'], "3.1")
        
        # Expectation: The vector string should have been transformed to include V3.1 prefixes
        # The exact vector depends on your CVSSHelper.upgrade_vector mapping logic.
        self.assertTrue(tokenized['vector'].startswith("CVSS:3.1"))
        
        # Expectation: The base_score should be a non-zero float calculated from the new vector
        self.assertGreater(tokenized['base_score'], 0.0)
        
        # Print for verification during test run
        # print(f"Upgraded Vector: {tokenized['vector']}")
        # print(f"Upgraded Score: {tokenized['base_score']}")


    @patch('requests.get')
    def test_query_vulnerabilities_not_found_returns_empty_dict(self, mock_get):
        """
        SCENARIO: The API returns a 404 or a non-200 error code.
        EXPECTED: Should return {} instead of None.
        """
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:invalid:product:1.0")
        
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 0)

    @patch('requests.get')
    def test_query_vulnerabilities_connection_error_returns_empty_dict(self, mock_get):
        """
        SCENARIO: A network-level exception occurs (RequestException).
        EXPECTED: Should return {} instead of None.
        """
        from requests.exceptions import ConnectionError
        mock_get.side_effect = ConnectionError("Network Down")

        result = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:vendor:product:1.0")
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})

    @patch('requests.get')
    def test_query_vulnerabilities_server_error_returns_empty_dict(self, mock_get):
        """
        SCENARIO: The NVD server returns a 500 Internal Server Error.
        EXPECTED: Should return {} instead of None.
        """
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:vendor:product:1.0")
        
        self.assertEqual(result, {})

    @patch('requests.get')
    @patch('time.sleep', return_value=None) # Don't actually wait during tests
    def test_nvd_rate_limit_retry(self, mock_sleep, mock_get):
        """Verifies that NVD client retries after a 429 error."""
        # Setup: First call returns 429, second returns 200
        mock_429 = MagicMock(status_code=429)
        mock_429.headers = {"Retry-After": "30"}
        
        mock_200 = MagicMock(status_code=200)
        mock_200.json.return_value = {"vulnerabilities": []}
        
        mock_get.side_effect = [mock_429, mock_200]

        result = self.nvd_client.query_for_vulnerabilities("cpe:2.3:a:any:thing:1.0")
        
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(result, {"vulnerabilities": []})


    @patch('time.time')
    @patch('time.sleep')
    @patch('requests.get')
    def test_rate_limit_termination(self, mock_get, mock_sleep, mock_time):
        # Initialize: 2 requests per 10-second window
        local_nvd = NVD("mock-key", max_requests=2, window_size=10)
        
        # Simulate time advancing: 
        # Call 1 & 2: First request (at t=100)
        # Call 3 & 4: Second request (at t=101)
        # Call 5+: Third request (starts at t=102, then jumps to t=112 after sleep)
        mock_time.side_effect = [100.0, 100.0, 101.0, 101.0, 102.0, 112.0, 112.0]

        # Mock successful responses
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"vulnerabilities": []})

        # Request 1 & 2: Should pass immediately
        local_nvd.query_for_vulnerabilities("cpe:1")
        local_nvd.query_for_vulnerabilities("cpe:2")
        
        # Request 3: Should trigger the loop, see the time jump to 112, and then exit
        local_nvd.query_for_vulnerabilities("cpe:3")

        # Verify sleep was called once to wait for the window to clear
        self.assertGreaterEqual(mock_sleep.call_count, 1)

if __name__ == '__main__':
    unittest.main()