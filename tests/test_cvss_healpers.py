import unittest
from helpers.cvss_helper import CVSSHelper

class TestCVSSHelper(unittest.TestCase):

    def test_get_score_calculation(self):
        """Tests calculation for multiple CVSS generations."""
        # Test 3.1
        v3_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(CVSSHelper.get_score_from_vector(v3_vec, "3.1"), 9.8)
        
        # Test 2.0
        v2_vec = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        self.assertEqual(CVSSHelper.get_score_from_vector(v2_vec, "2.0"), 7.5)

    def test_cvss2_to_cvss3_transformation(self):
        """Tests mapping of legacy 'Authentication' to 'Privileges Required'."""
        v2_vec = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        upgraded = CVSSHelper.cvss2_to_cvss3(v2_vec)
        
        # In your code: Au:N becomes PR:N and Partial (P) becomes Low (L)
        self.assertIn("PR:N", upgraded)
        self.assertIn("C:L/I:L/A:L", upgraded)
        self.assertTrue(upgraded.startswith("CVSS:3.1"))

    def test_iterative_upgrade_2_to_4(self):
        """Tests the logic that 'steps' a vector from 2.0 to 4.0."""
        v2_vec = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        
        # Step through 2.0 -> 3.1 -> 4.0
        final_vec, final_ver = CVSSHelper.upgrade_vector(v2_vec, "2.0", "4.0")
        
        self.assertEqual(final_ver, "4.0")
        self.assertTrue(final_vec.startswith("CVSS:4.0"))
        # Verify CVSS 4.0 specific metrics like 'Vulnerable System Confidentiality' (VC)
        self.assertIn("VC:L", final_vec)

    def test_tokenize_human_readable(self):
        """Tests conversion of AV:N to 'Network'."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        # Test human_readable=True
        readable = CVSSHelper.tokenize_cvss3_human(vec, human_readable=True)
        self.assertEqual(readable["AV"], "Network")
        self.assertEqual(readable["UI"], "None")
        
        # Test human_readable=False
        raw = CVSSHelper.tokenize_cvss3_human(vec, human_readable=False)
        self.assertEqual(raw["AV"], "N")

    def test_tokenize_invalid_version(self):
        """Verifies that tokenize only accepts CVSS v3."""
        with self.assertRaises(TypeError):
            CVSSHelper.tokenize_cvss3_human("AV:N/AC:L/Au:N/C:P/I:P/A:P")

if __name__ == '__main__':
    unittest.main()