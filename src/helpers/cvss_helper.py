from cvss import CVSS2, CVSS3, CVSS4

class CVSSHelper:
    """
    A utility class for CVSS vector normalization, scoring, and translation.

    This class provides the logic to bridge the gap between different generations 
    of the Common Vulnerability Scoring System, allowing legacy data to be 
    represented in modern formats.
    """

    @staticmethod
    def get_score_from_vector(vector_str: str, version: str) -> float:
        """
        Calculates the Base Score from a vector string.

        Args:
            vector_str (str): The raw CVSS vector (e.g., "AV:N/AC:L/...").
            version (str): The version string ("2.0", "3.0", "3.1", or "4.0").

        Returns:
            float: The calculated base score (0.0 to 10.0).
        """
        try:
            if "CVSS:4.0" in vector_str or version == "4.0":
                return float(CVSS4(vector_str).base_score)
            if "CVSS:3" in vector_str or version in ["3.0", "3.1"]:
                return float(CVSS3(vector_str).base_score)
            if "CVSS:2" in vector_str or version == "2.0":
                return float(CVSS2(vector_str).base_score)
        except Exception as e:
            print(f"Error calculating score for {vector_str}: {e}")
        return 0.0

    @staticmethod
    def cvss2_to_cvss3(v2_str: str) -> str:
        """
        Approximates a CVSS v2.0 vector as a v3.1 vector.
        
        Note:
            v2 'Authentication' is mapped to v3 'Privileges Required'.
            v2 'Partial/Complete' impacts are mapped to v3 'Low/High'.
        """
        try:
            c2 = CVSS2(v2_str)
            m2 = c2.metrics
            impact_map = {'N': 'N', 'P': 'L', 'C': 'H'}
            
            ac_v3 = 'L' if m2['AC'] == 'L' else 'H'
            pr_v3 = 'N' if m2['Au'] == 'N' else 'L'

            return (
                f"CVSS:3.1/AV:{m2['AV']}/AC:{ac_v3}/PR:{pr_v3}/UI:N/S:U/"
                f"C:{impact_map[m2['C']]}/I:{impact_map[m2['I']]}/A:{impact_map[m2['A']]}"
            )
        except Exception:
            return v2_str

    @staticmethod
    def cvss3_to_cvss4(v31_str: str) -> str:
        """
        Approximates a CVSS v3.1 vector as a v4.0 vector.
        
        Handles the transition of 'Scope' to 'Subsequent System' metrics.
        """
        try:
            c3 = CVSS3(v31_str)
            ui_v4 = 'A' if c3.metrics['UI'] == 'R' else 'N'
            
            # If Scope is Changed, move impacts to Subsequent System VC/VI/VA -> SC/SI/SA
            sc, si, sa = (c3.metrics['C'], c3.metrics['I'], c3.metrics['A']) if c3.metrics['S'] == 'C' else ('N', 'N', 'N')

            return (
                f"CVSS:4.0/AV:{c3.metrics['AV']}/AC:{c3.metrics['AC']}/AT:N/PR:{c3.metrics['PR']}/UI:{ui_v4}/"
                f"VC:{c3.metrics['C']}/VI:{c3.metrics['I']}/VA:{c3.metrics['A']}/SC:{sc}/SI:{si}/SA:{sa}"
            )
        except Exception:
            return v31_str

    @classmethod
    def upgrade_vector(cls, vector_str: str, current_ver: str, target_ver: str):
        """
        Iteratively upgrades a vector to a higher target version.

        Args:
            vector_str (str): The starting vector.
            current_ver (str): Current version (e.g., "2.0").
            target_ver (str): Desired version (e.g., "4.0").

        Returns:
            tuple: (upgraded_vector_string, final_version_string)
        """
        work_vector = vector_str
        work_ver = current_ver

        while work_ver != target_ver:
            if work_ver == "2.0":
                work_vector = cls.cvss2_to_cvss3(work_vector)
                work_ver = "3.1"
            elif work_ver == "3.1" or work_ver == "3.0":
                work_vector = cls.cvss3_to_cvss4(work_vector)
                work_ver = "4.0"
            else:
                break
        
        return work_vector, work_ver

    @staticmethod
    def tokenize_cvss3_human(vector_string: str, human_readable: bool=True) -> dict:
        """
        Explodes a CVSS v3 vector into a dictionary of descriptive names.

        Example:
            "AV:N" becomes {"AV": "Network"} if human_readable is True.
        """
        CVSS_MAP = {
            "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
            "AC": {"L": "Low", "H": "High"},
            "PR": {"N": "None", "L": "Low", "H": "High"},
            "UI": {"N": "None", "R": "Required"},
            "S":  {"U": "Unchanged", "C": "Changed"},
            "C":  {"N": "None", "L": "Low", "H": "High"},
            "I":  {"N": "None", "L": "Low", "H": "High"},
            "A":  {"N": "None", "L": "Low", "H": "High"}
        }

        if not vector_string.startswith("CVSS:3"):
            raise TypeError(f"Only CVSS3 can be tokenized: {vector_string}")

        # Remove the header (CVSS:3.x/)
        vector = vector_string.strip()
        if "/" in vector:
            vector = vector.split("/", 1)[1]

        readable_components = {}
        try:
            for part in vector.split("/"):
                if not part: continue
                key, val = part.split(":")
                if human_readable:
                    human_value = CVSS_MAP.get(key, {}).get(val, val)
                else:
                    human_value = val
                readable_components[key] = human_value
            return readable_components
        except ValueError:
            raise ValueError(f"Invalid CVSS format: {vector_string}")