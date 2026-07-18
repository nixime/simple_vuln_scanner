--- RAW MARKDOWN CONTENT FOR README.MD (Select All & Copy) ---

# NVD & OSV BOM Scanner & Orchestrator

> **AI Disclosure:** Parts of the code in this repository were developed through a collaboration between human expertise and AI assistance. The core logic has been manually reviewed, tweaked, and tested to ensure mathematical accuracy and stability.

This tool is a powerful vulnerability orchestrator that aggregates threat intelligence from multiple upstream security databases and maps them directly into automated, beautifully formatted Excel risk assessments.

The orchestrator operates in two distinct modes based on your architecture:
1. **Local Manifest Processing:** Ingests flat **CSV** inventory files or **CycloneDX JSON** Bill of Materials (SBOM) to query vulnerabilities via CPE or PURL.
2. **Dependency-Track Integration:** Connects directly to a remote server management instance using a project/system UUID to collect pre-computed system-level metrics natively.

---

## 🚀 Key Features

* **Dual-Mode Orchestration:** Seamlessly switch between parsing local SBOM files or connecting directly to **Dependency-Track** server UUIDs.
* **Multi-Source Threat Intelligence:** Aggregates data from **NVD** (CPE scanning) and **Google OSV** (PURL scanning).
* **CISA KEV Enrichment:** Automatically cross-references vulnerabilities against the CISA Known Exploited Vulnerabilities catalog to flag active in-the-wild threats.
* **Bulk EPSS Integration:** Fetches Exploit Prediction Scoring System (EPSS) probability scores via First.org to weigh real-world exploit likelihood against traditional CVSS severity.
* **Automated Excel Formatting:** Injects data into a master template, applies uniform conditional styles, binds data validation dropdowns, and generates clean management-ready workbooks.

---

## ⚠️ Important Considerations

* **API Access:** You must register at the [NVD website](https://nvd.nist.gov/) to obtain a personal NVD API key to use this tool.
* **CVSS Conversion:** This tool utilizes custom code to normalize older CVSSv2 scores into CVSSv3. Please be aware that this conversion process may result in slight variances in the final base risk assessment compared to original CVSSv2 values.
* **EPSS (Exploit Prediction Scoring System):** A data-driven metric that estimates the probability ($0.0$ to $1.0$) that a software vulnerability will be exploited in the wild within the next 30 days. Unlike CVSS, which measures severity, EPSS measures actual threat and likelihood. This data is pulled from First.org.

---

## Setup & Installation

It is recommended to run this tool within a dedicated virtual environment to maintain clean dependency management.

### 1. Initialize Environment

```bash
# Create and activate the virtual environment
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies

Ensure your environment is active, then run:

```bash
pip install requests openpyxl cyclonedx-python-lib cvss osv
```

*Note: The `json` and `csv` libraries are included in the Python standard library and do not require manual installation via pip.*

---

## 🛠️ Configuration & Usage

To run the scanner, you must provide your upstream API keys and establish your template layouts inside a central `config.ini` file. For a complete deep-dive into advanced configuration metrics, column mapping, and formula controls, see the [Configuration Reference](CONFIGURATION.md).

### Command Line Interface

```bash
python3 main.py [OPTIONS]
```

#### Available Arguments:
| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--config` | `string` | `config.ini` | Path to the main global configuration `.ini` file. |
| `--outdir` | `string` | *(Current Dir)* | Output directory where the generated Excel reports will be saved. |
| `--system_override` | `string` | *None* | Direct path to a specific `System.ini` file to process instead of the global configuration list. |
| `--start` | `YYYY-MM-DD` | *None* | Filter to only include vulnerabilities published **after** this date. |
| `--end` | `YYYY-MM-DD` | *None* | Filter to only include vulnerabilities published **before** this date. |
| `--verbose` | `flag` | *False* | Enables detailed console logging, API status tracing, and debug outputs. |
