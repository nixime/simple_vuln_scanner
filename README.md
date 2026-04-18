# NVD & OSV BOM Scanner

> **AI Disclosure:** Parts of the code in this repository were developed through a collaboration between human expertise and AI assistance. The core logic has been manually reviewed, tweaked, and tested to ensure mathematical accuracy and stability.

This tool aggregates vulnerability data from the **National Vulnerability Database (NVD)** and the **Google Open Source Vulnerability (OSV)** database to populate a custom Excel template. The tool supports ingesting **CSV** or **CycloneDX** files containing CPEs or package identifiers (PURL).

There is also a [migration script](README2.md), to enable copying manually populated data from a prior assessment to the newly scanned content.

## ⚠️ Important Considerations

* **Dual-Source Vulnerability Scanning:** This tool aggregates vulnerability data from two primary sources:
    * **NVD:** Used for CPE Scanning (Requires a registered NVD API key).
    * **Google OSV:** Used for PURL scanning
* **CVSS Conversion:** This tool utilizes the `cvss_converter` library to normalize CVSSv2 scores into CVSSv3. Please be aware that this conversion process may result in slight variances in the final base risk assessment compared to original CVSSv2 values.
* **API Access:** You must register at the [NVD website](https://nvd.nist.gov/) to obtain a personal NVD API key to use this tool.
* **EPSS (Exploit Prediction Scoring System):** A data-driven metric that estimates the probability (0.0 to 1.0) that a software vulnerability will be exploited in the wild within the next 30 days. Unlike CVSS, which measures severity, EPSS measures actual threat and likelihood. This data is pulled from First.org

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


