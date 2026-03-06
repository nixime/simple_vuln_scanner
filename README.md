# NVD & OSV BOM Scanner

This tool aggregates vulnerability data from the **National Vulnerability Database (NVD)** and the **Google Open Source Vulnerability (OSV)** database to populate a custom Excel template. The tool supports ingesting **CSV** or **CycloneDX** files containing CPEs or package identifiers (PURL).


## ⚠️ Important Considerations

* **Dual-Source Vulnerability Scanning:** This tool aggregates vulnerability data from two primary sources:
    * **NVD:** Utilized for broad CVE coverage. (Requires a registered NVD API key).
    * **Google OSV:** Utilized for precise, ecosystem-specific open-source vulnerability mapping via the `osv` Python library. This helps significantly reduce false positives and fills gaps where NVD data may be delayed.
* **CVSS Conversion:** This tool utilizes the `cvss_converter` library to normalize CVSSv2 scores into CVSSv3. Please be aware that this conversion process may result in slight variances in the final base risk assessment compared to original CVSSv2 values.
* **API Access:** You must register at the [NVD website](https://nvd.nist.gov/) to obtain a personal NVD API key to use this tool.


## Setup & Installation

It is recommended to run this tool within a dedicated virtual environment to maintain clean dependency management.

### 1. Initialize Environment

```bash
# Create and activate the virtual environment
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependancies

Ensure your environment is active, then run:

```bash
pip install requests openpyxl cyclonedx-python-lib cvss_converter osv
```

Note: The json library is included in the Python standard library and does not require manual installation via pip.


## Configuration
To run the scanner, you must provide an NVD API key and define your template path in `config.ini`. 

For a complete reference of all available settings—including advanced column mapping, CVSS vector splitting, and formula customization—please see the [Configuration Reference](CONFIGURATION.md).
