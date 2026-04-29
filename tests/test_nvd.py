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

if __name__ == '__main__':
    unittest.main()