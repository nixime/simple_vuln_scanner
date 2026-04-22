#!/usr/bin/env python3
"""
Vulnerability Scanner Orchestrator

This script serves as the main entry point for the vulnerability scanning application.
Key features and workflow:
1. Parses CLI arguments for configurations, date filters, and output directories.
2. Initializes API clients for NVD, OSV, CISA (KEV), and EPSS.
3. Loads Excel templates and system-specific configurations.
4. Iterates through Software Bill of Materials (SBOMs) in CSV or CycloneDX format.
5. Queries multiple vulnerability databases based on component identifiers (CPE/PURL).
6. Aggregates results, applies risk scores (EPSS/KEV), and generates a formatted Excel Report.
"""

import argparse
import sys
import os
import csv
import json
import time
import copy
from pathlib import Path
from collections import namedtuple
from datetime import datetime

# Excel and Data Modeling
from openpyxl import load_workbook
from cyclonedx.model.bom import Bom

# Custom Modules
import config_handler
import core.nvd as nvd
import core.cisa as cisa
import core.osv as osv
import core.epss as epss
from helpers.excel_utilities import ExcelHelper

def get_component_list(file: str, type: str, csv_column_id: int):
    """
    Extracts component identifiers from a source file.
    Args:
        file (str): Path to the BOM file.
        type (str): 'csv' or 'json' (CycloneDX).
        csv_column_id (int): The column index to read if the file is a CSV.
    Returns:
        list: A list of CPE or PURL strings.
    """
    cpe_list = []
    if type.lower() == "csv":
        with open(file, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) > csv_column_id:
                    cpe_list.append(row[csv_column_id].strip())
    else:
        # CycloneDX JSON Parsing
        with open(file, 'r') as f:
            json_data = json.load(f)
        bom = Bom.from_json(data=json_data)
        for component in bom.components:
            if component.cpe:
                cpe_list.append(str(component.cpe))
            elif component.purl:
                cpe_list.append(str(component.purl))
    return cpe_list

def valid_date(s):
    """Argparse type validator for YYYY-MM-DD strings."""
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = f"Not a valid date: '{s}'. Expected format: YYYY-MM-DD."
        raise argparse.ArgumentTypeError(msg)

def main():
    # CLI Setup
    parser = argparse.ArgumentParser(
        description="Scan NVD/OSV for vulnerabilities associated with CPE/PURL inputs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--config", type=str, help="Path to main .ini config")
    parser.add_argument("--load", type=str, help="Load a pre-existing JSON dump for offline testing")
    parser.add_argument("--outdir", type=str, help="Output directory for generated Excel files")
    parser.add_argument("--system_override", type=str, help="Specific System.ini to process")
    parser.add_argument("--start", type=valid_date, help="Filter vulnerabilities published AFTER this date")
    parser.add_argument("--end", type=valid_date, help="Filter vulnerabilities published BEFORE this date")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed debug logging to console")
    args = parser.parse_args()

    if args.verbose:
        print(f"[*] Starting Orchestrator at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Configuration & Resource Initialization
    config_arg = args.config if args.config and os.path.exists(args.config) else 'config.ini'
    config_file = Path(config_arg).resolve()
    config_root = Path(config_file).parent
    
    if args.verbose:
        print(f"[*] Loading master configuration: {config_file}")
    
    config = config_handler.NVDConfigFile(config_file)

    # SSL and Scoring setup
    val_cert = getattr(config.GLOBAL, "validate_remote_certificate", True)
    score_ver = getattr(config.GLOBAL, "score_system_ver", "3.1")

    # API Client Factory
    if args.verbose:
        print("[*] Initializing API clients and loading KEV database...")
    nvd_obj = nvd.NVD(config.NVD.api_key, val_cert, score_ver)
    osv_obj = osv.OSV(20, val_cert)
    kev_obj = cisa.KEV(val_cert)
    kev_obj.load_kevs()

    template_file = Path(config_root) / config.TEMPLATE.template
    if not template_file.exists():
        raise FileNotFoundError(f"Template not found: {template_file}")

    # Global Processing Flags
    include_zero = getattr(config.GLOBAL, "include_zero_vuln_components", False)
    include_deferred = not getattr(config.GLOBAL, "ignore_defferred", False)
    system_configs = [args.system_override] if args.system_override else config.GLOBAL.input_configs

    if args.verbose:
        print(f"[+] Found {len(system_configs)} system(s) to process.")

    # Main Processing Loop (Per System)
    for system in system_configs:
        if args.verbose:
            print(f"\n>>> Processing System Config: {system}")
            
        system_config = config_handler.SystemConfigFile(system)
        system_root_path = Path(system).resolve().parent

        clean_system_name = system_config.name[:31]
        combine_sboms = getattr(system_config, "combine_all_boms", False)

        # Prepare Workbook
        wb = load_workbook(filename=template_file, keep_vba=True)
        template_name = getattr(config.TEMPLATE, "template_sheet_name", wb.sheetnames[0])
        template_sheet = wb[template_name]
        _, template_ext = os.path.splitext(template_file)
        
        new_sheet = template_sheet if combine_sboms else None
        data_row = config.TEMPLATE.template_start_row
        row_count = 0

        # System SBOM Processing, iterate over each SBOM within a system and gather the data
        for bom in system_config.boms:
            full_bom = Path(system_root_path) / bom
            clean_name = Path(full_bom).stem[:31]
            epss_manager = epss.EPSS(verify_certificate=val_cert)

            if args.verbose:
                print(f"  [*] Analyzing SBOM: {full_bom.name}")

            # Sheet setup for individual BOM reports
            if not combine_sboms:
                new_sheet = wb.copy_worksheet(template_sheet)
                if template_sheet.auto_filter.ref:
                    new_sheet.auto_filter.ref = template_sheet.auto_filter.ref
                ExcelHelper.copy_data_validations(template_sheet, new_sheet)
                new_sheet.title = f"RA_{clean_name}"
                data_row = config.TEMPLATE.template_start_row
                row_count = 0

            csv_col = getattr(system_config, "bom_cpe_column", 0)
            component_list = get_component_list(full_bom, system_config.bom_format, csv_col)

            if args.verbose:
                print(f"  [+] Extracted {len(component_list)} components.")

            # Component Analysis Loop
            for component_id in component_list:
                # API Rate Limiting Logic
                limit = config.RATE_LIMITER.requests_per_delay
                if row_count > 0 and row_count % limit == 0:
                    if args.verbose:
                        print(f"    [!] Rate limit reached. Sleeping for {config.RATE_LIMITER.request_delay}s...")
                    time.sleep(config.RATE_LIMITER.request_delay)

                # Determine Source (NVD for CPE, OSV for PURL)
                if component_id.startswith("cpe:"):
                    source_obj = nvd_obj
                    source_label = "NVD"
                elif component_id.startswith("pkg:"):
                    source_obj = osv_obj
                    source_label = "OSV"
                else:
                    if args.verbose:
                        print(f"    [-] Skipping unknown identifier format: {component_id}")
                    continue

                if args.verbose:
                    print(f"    [?] Querying {source_label} for: {component_id}")

                obj_json = source_obj.query_for_vulnerabilities(component_id)
                vulns_list = obj_json.get('vulnerabilities', obj_json.get('vulns', []))

                # Handle components with no identified vulnerabilities
                if not vulns_list:
                    if include_zero:
                        ExcelHelper.populate_template_sheet(
                            new_sheet, data_row, config.TEMPLATE, clean_name, component_id, 
                            'None', 'No Vulnerabilities Found', 'N/A', 'N/A', 0, False
                        )
                        data_row += 1
                        row_count += 1
                    continue

                # Vulnerability Detail Extraction
                for vuln in vulns_list:
                    v_data = source_obj.tokenize_vuln(vuln)

                    # Apply Date and Status filters
                    pub_dt = datetime.fromisoformat(v_data['published'].replace('Z', '+00:00')).replace(tzinfo=None)
                    if (args.start and pub_dt < args.start) or (args.end and pub_dt > args.end):
                        continue
                    if v_data['status'] == "Deferred" and not include_deferred:
                        continue

                    # Risk Intelligence Enrichment
                    is_kev = kev_obj.query_cpe(v_data['cve_id']) if v_data['cve_id'].startswith("CVE-") else False
                    if v_data['cve_id'].startswith("CVE-"):
                        epss_manager.register_cve(cve_id=v_data['cve_id'], indexer_id=data_row)

                    # Populate Excel row
                    ExcelHelper.populate_template_sheet(
                        new_sheet, data_row, config.TEMPLATE, clean_name, component_id,
                        v_data['cve_id'], v_data['description'], v_data['published'],
                        v_data['vector'], v_data['base_score'], is_kev
                    )
                    data_row += 1
                    row_count += 1

            # Finalize Report and append secondary risk data
            if row_count > 0:
                if args.verbose:
                    print(f"  [*] Fetching bulk EPSS scores for {clean_name}...")
                epss_manager.query() 
                ExcelHelper.populate_epss_data(new_sheet, config.TEMPLATE, epss_manager)

            if not combine_sboms:
                print(f"  [*] Applying Excel Formatting and Content (Individual SBOM)...")
                ExcelHelper.apply_static_content(config.TEMPLATE, template_sheet, new_sheet, config.TEMPLATE.template_start_row, row_count)
                ExcelHelper.apply_formatting_to_range(new_sheet, config.TEMPLATE.template_start_row, config.TEMPLATE.template_start_row + 1, row_count)
                ExcelHelper.apply_data_validation_rules(new_sheet, config.TEMPLATE.template_start_row, row_count)

        if combine_sboms:
            print(f"[*] Applying Excel Formatting and Content (Combined SBOM)...")
            ExcelHelper.apply_static_content(config.TEMPLATE, template_sheet, new_sheet, config.TEMPLATE.template_start_row, row_count)
            ExcelHelper.apply_formatting_to_range(new_sheet, config.TEMPLATE.template_start_row, config.TEMPLATE.template_start_row + 1, row_count)
            ExcelHelper.apply_data_validation_rules(new_sheet, config.TEMPLATE.template_start_row, row_count)
        
        # Workbook cleanup and saving
        if not combine_sboms:
            wb.remove(wb[template_name])
            
        save_path = f"{args.outdir}/" if args.outdir else ""
        out_file = f"{save_path}{clean_system_name}{template_ext}"
        wb.save(out_file)
        
        if args.verbose:
            print(f"[SUCCESS] Report generated: {out_file}")

if __name__ == "__main__":
    main()