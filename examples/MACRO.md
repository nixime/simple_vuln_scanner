# CVSS v3.1 Universal Macro Calculator

A best attempt at a compatible VBA macro designed to calculate CVSS v3.1 scores. The script is written to (in-theory) work seamlessly in both **Microsoft Excel** and **LibreOffice Calc** without requiring external lookup tables or complex API calls.



## Logic Overview

The macro is based on the FIRST.org CVSS v3.1 equations. It translates human-readable security metrics (e.g., "Network", "High", "Low") into numeric weights and processes them through the standard impact and exploitability formulas.

### 1. Constant Weights (Hardcoded)
To ensure portability and avoid "broken link" errors, all weights are defined as global constants at the top of the module.

| Metric | Values & Weights |
| :--- | :--- |
| **Attack Vector (AV)** | Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.2), N/A (0) |
| **Attack Complexity (AC)** | Low (0.77), High (0.44), N/A (0) |
| **User Interaction (UI)** | None (0.85), Required (0.62), N/A (0) |
| **Privileges Required (PR)** | *Scope Dependent:* (None: 0.85, Low: 0.62/0.68, High: 0.27/0.50), N/A (0) |
| **CIA (C, I, A)** | None (0.0), Low (0.22), High (0.56) |

### 2. Core Formulas
The script executes the following mathematical sequence:

1.  **ISS (Impact Sub Score):**
    $$ISS = 1 - [(1 - \text{Conf}) \times (1 - \text{Integ}) \times (1 - \text{Avail})]$$

2.  **Impact:**
    * *If Scope Unchanged:* $6.42 \times ISS$
    * *If Scope Changed:* $7.52 \times (ISS - 0.029) - 3.25 \times (ISS \times 0.9731 - 0.02)^{13}$

3.  **Exploitability:**
    $$8.22 \times AV \times AC \times PR \times UI$$

4.  **Base Score:**
    If Impact is $\le 0$, the score is $0$. Otherwise, it combines Impact and Exploitability (applying a $1.08$ multiplier if Scope is Changed) and caps the result at $10$.


## Installation & Setup

### For Microsoft Excel
1.  Open your workbook and press `Alt + F11` to open the VBA Editor.
2.  Go to `Insert > Module`.
3.  Paste the code into the module.
4.  Save the file as an **Excel Macro-Enabled Workbook (.xlsm)**.

### For LibreOffice Calc
1.  Go to `Tools > Macros > Organize Macros > Basic`.
2.  Select your document, click `New`, and name the module (e.g., `CVSS_Logic`).
3.  Paste the code. **Crucial:** Ensure `Option VBASupport 1` remains at the very top.
4.  Set Macro Security to **Medium** (`Tools > Options > LibreOffice > Security`).


## Usage in Template
Once installed, use the function in any cell like a standard formula:

```excel
=GET_CVSS(AV, AC, PR, UI, Scope, Conf, Integ, Avail)
```