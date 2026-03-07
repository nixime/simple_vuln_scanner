# MIGRATION SCRIPT

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
pip install openpyxl
```

## Configuration
To run the migration script you need to provide multiple inputs on the command line, as detailed below:

| Parameter | Description|
| --- | --- |
| --source | The original file containing the prior assessment |
| --destination | The recently run vulnerability output |
| --columns | A list of column (letters) that need to be migrated from the source to desination |
| --match | The column in the source containing the unique identifier to match on |

### Example
```bash
migrate.py --source "System 1.old.xlsx" --destination "System 1.xlsx" --columns "A" "J" "K" "L" "M" "N" "O" "P" "Q" "R" "S" "T" "W" --match "D"
```