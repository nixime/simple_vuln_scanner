# Configuration
The tool uses 2 configuration files `config.ini` and multiple `system.ini` to define the behavior of the tool and the definition of the system under test.


## Script Configuration Reference
The tool is controlled via the `config.ini` file. Below is a breakdown of the primary settings.

### [NVD]
* **`api_key`**: Your personal NVD API key.
* **`requests_per_delay`**: Number of API requests allowed before a delay is applied.
* **`request_delay`**: Duration of the delay in seconds.

### [DT]
* **`url`**: Base URL where the dependency track system is hosted (URL part before "/api", including the "http" or "https")
* **`key`**: Key used for authentication to DT

### [GLOBAL]
* **`score_system_ver`**: Specifies the CVSS version to be targeted for analysis. Valid options are `3.1` or `4.0`.
* **`input_configs`**: Path to the system configuration file.
* **`ignore_defferred`**: Boolean to skip CVEs marked as deferred.
* **`include_zero_vuln_components`**: Boolean to include components with no reported vulnerabilities.
* **`validate_remote_certificate`**: Should we validate the remote HTTPS connections (disable if you are behind proxys or such that interfere)
* **`source_locations`**: Which type of data sources should be used? Valid values are "osv","nvd" and "dependancy_track". If DT is chosen then the other items will be ignored as it provides both PURL and CPEs.
* **`verbose_logging`**: Should verbose logging be enabled on the command line

### [TEMPLATE]
This section manages how data is mapped to your Excel file.
* **`template`**: Path to your `.xlsx` template file.
* **`template_start_row`**: The starting row index for data entry.
* **`combine_all_boms`**: If `True`, aggregates all data into a single worksheet.
* **`split_cvss_score`**: If `True`, splits the CVSS vector into individual component parts for the template.

#### Column Mapping
The tool allows granular control over which column in your Excel template receives specific data points; either letters or a 1-based index integer are allowed. None of these values are required and you can choose which ones to include or exclude in your script.

> **Note on CVSS Versions:** Metric mappings differ significantly between CVSS v3.x and CVSS v4.0. Please verify your template columns match the target version specified in `score_system_ver`.

| Parameter | Supported Version | Description |
| :--- | :--- | :--- |
| `column_id_bom` | All | Column index for BOM identifier |
| `column_id_cpe` | All | Column index for CPE strings |
| `column_id_cve` | All | Column index for CVE identifiers |
| `column_id_description` | All | Column index for vulnerability descriptions |
| `column_id_publish_date` | All | Column index for CVE publication date |
| `column_id_cvss` | All | Column index for the raw CVSS vector string |
| `column_id_base_score` | All | Column index for the numerical base score |
| `column_id_is_kev` | All | Column index to flag if the CVE is in the KEV catalog |
| `column_id_epss` | All | Column index to flag if EPSS risk rating should be included |
| `column_split_cvss_av` | All | Column index for CVSS Attack Vector |
| `column_split_cvss_ac` | All | Column index for CVSS Attack Complexity |
| `column_split_cvss_pr` | All | Column index for CVSS Privileges Required |
| `column_split_cvss_ui` | All | Column index for CVSS User Interaction |
| `column_split_cvss_s` | **CVSS v3.x Only** | Column index for CVSS Scope |
| `column_split_cvss_c` | **CVSS v3.x Only** | Column index for CVSS Confidentiality Impact |
| `column_split_cvss_i` | **CVSS v3.x Only** | Column index for CVSS Integrity Impact |
| `column_split_cvss_a` | **CVSS v3.x Only** | Column index for CVSS Availability Impact |
| `column_split_cvss_at` | **CVSS v4.0 Only** | Column index for CVSS Attack Requirements |
| `column_split_cvss_vc` | **CVSS v4.0 Only** | Column index for CVSS Vulnerable System Confidentiality Impact |
| `column_split_cvss_vi` | **CVSS v4.0 Only** | Column index for CVSS Vulnerable System Integrity Impact |
| `column_split_cvss_va` | **CVSS v4.0 Only** | Column index for CVSS Vulnerable System Availability Impact |
| `column_split_cvss_sc` | **CVSS v4.0 Only** | Column index for CVSS Subsequent System Confidentiality Impact |
| `column_split_cvss_si` | **CVSS v4.0 Only** | Column index for CVSS Subsequent System Integrity Impact |
| `column_split_cvss_sa` | **CVSS v4.0 Only** | Column index for CVSS Subsequent System Availability Impact |

#### Advanced Customization
You can inject static Excel formulas into specific columns to perform post-processing calculations. 'x' must be replaced by an incrementing number such that each number has both an id and value column identified (e.g column_static_1_id, column_static_1_value, column_static_2_id, etc)

* **`column_static_x_id`**: The column index within the template where the static content will be injected
* **`column_static_x_value`**: (OPTIONAL) A formula or other static data to inject into the excel file. If not provided, then the existing formula in the cell will be used and copied


## System Configuration Reference

This file defines the systems and associated Bills of Materials (BOMs) that the scanner will process. Each system is defined by its own section header (e.g., `[SYSTEM_ID_1]`).

## System Configuration Reference

This file defines the systems and associated Bills of Materials (BOMs) that the scanner will process. Each system is defined by its own section header (e.g., `[SYSTEM_ID_1]`).

## System Configuration Parameters

System configuration parameters allow you to define settings for individual systems, including overriding global choices for specific scanning workflows.

| Parameter | Required | Description |
| :--- | :--- | :--- |
| `name` | **Yes** | A descriptive name for the system being scanned. |
| `boms` | **Yes (If NVD or OSV)** | The file path to the BOM input file. |
| `bom_format` | **Yes (If NVD or OSV)** | The format of the BOM file. Valid options: `csv` or `json` (CycloneDX). |
| `bom_cpe_column` | **No (If NVD or OSV)** | The column index for CPEs if the format is set to `csv`. |
| `template` | **No** | The template file to use for this system, if overriding the global configuration value. |
| `source_locations` | **No** | Overrides the global `[GLOBAL]` data source setting for this specific system (e.g., targeting only `"dependancy_track"` while others run on `"nvd"`). |
| `system_uuid` | **No** | The Dependency-Track (DT) project UUID unique to this system. Use this parameter when querying a specific project instance directly from DT. |


> **Note on Upstream Mapping:** For more detailed examples on how these identifiers map to upstream projects or to see a full configuration architecture blueprint, please refer to the structure documented in **CONFIGURATION.md**.