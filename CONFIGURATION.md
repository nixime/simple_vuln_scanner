# Configuration
The tool uses 2 configuration files `config.ini` and multiple `system.ini` to define the behavior of the tool and the definition of the system under test.


## Script Configuration Reference
The tool is controlled via the `config.ini` file. Below is a breakdown of the primary settings.

### [NVD]
* **`api_key`**: Your personal NVD API key.

### [GLOBAL]
* **`input_configs`**: Path to the system configuration file.
* **`ignore_defferred`**: Boolean to skip CVEs marked as deferred.
* **`include_zero_vuln_components`**: Boolean to include components with no reported vulnerabilities.

### [TEMPLATE]
This section manages how data is mapped to your Excel file.
* **`template`**: Path to your `.xlsx` template file.
* **`template_start_row`**: The starting row index for data entry.
* **`combine_all_boms`**: If `True`, aggregates all data into a single worksheet.
* **`split_cvss_score`**: If `True`, splits the CVSS vector into individual parts for the template.

#### Column Mapping
The tool allows granular control over which column in your Excel template receives specific data points, either letters or a 1-based index integer are allowed. None of these values are required and you can choose which ones to include or not include in your script.

| Parameter | Description |
| :--- | :--- |
| `column_id_bom` | Column index for BOM identifier |
| `column_id_cpe` | Column index for CPE strings |
| `column_id_cve` | Column index for CVE identifiers |
| `column_id_description` | Column index for vulnerability descriptions |
| `column_id_publish_date` | Column index for CVE publication date |
| `column_id_cvss` |  Column index for the CVSS score |
| `column_id_base_score` | Column index for the base CVSS score |
| `column_id_is_kev` |  Column index to flag if the CVE is in the KEV catalog |
| `column_split_cvss_av` | Column index for CVSS Attack Vector |
| `column_split_cvss_ac` | Column index for CVSS Attack Complexity |
| `column_split_cvss_pr` | Column index for CVSS Privileges Required |
| `column_split_cvss_ui` | Column index for CVSS User Interaction |
| `column_split_cvss_s` | Column index for CVSS Scope |
| `column_split_cvss_c` | Column index for CVSS Confidentiality Impact |
| `column_split_cvss_i` | Column index for CVSS Integrity Impact |
| `column_split_cvss_a` | Column index for CVSS Availability Impact |

#### Advanced Customization
You can inject static Excel formulas into specific columns to perform post-processing calculations. 'x' must be replaced by an incrementing number such that each number has both and id and value column identified (e.g column_static_1_id, column_static_1_value, column_static_2_id, etc)

* **`column_static_x_id`**: The column index within the template where the static content will be injected
* **`column_static_x_value`**: (OPTIONAL) A formula or other static data to inject into the excel file. If not provided, then the existing formula in the cell will be used and copied

### [RATE_LIMITER]
This will be applied to total API calls, and not individual (e.g. NVD, OSV) calls themselves.

* **`requests_per_delay`**: Number of API requests allowed before a delay is applied.
* **`request_delay`**: Duration of the delay in seconds.


## System Configuration Reference

This file defines the systems and associated Bills of Materials (BOMs) that the scanner will process. Each system is defined by its own section header (e.g., `[SYSTEM_ID_1]`).

## System Configuration Parameters

| Parameter | Required | Description |
| :--- | :--- | :--- |
| `name` | **Yes** | A descriptive name for the system being scanned. |
| `boms` | **Yes** | The file path to the BOM input file. |
| `bom_format` | **Yes** | The format of the BOM file. Valid options: `csv` or `json` (CycloneDX). |
| `bom_cpe_column` |  The column index for CPEs if the format is set to `csv`. |
