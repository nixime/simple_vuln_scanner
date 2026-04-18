#!/usr/bin/env python3
# Import Full Python Libraries
import argparse
import sys
import os
import csv
import json
import csv
import time
import copy
# Selective Imports
from pathlib import Path
from collections import namedtuple
from openpyxl import load_workbook
from openpyxl.utils import range_boundaries, get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.formula.translate import Translator
from cyclonedx.model.bom import Bom
from datetime import datetime
# Custom Imports
import nvdconfig
import nvd
import cisa
import osv
import epss

def tokenize_cvss3_human(vector_string: str, human_readible: bool=True) -> dict:
    '''
    Static method to tokenize the CVSS 3.0 vector string into individual components

    Args:
        vector_string: String containing the CVSS vector for parsing
        human_readible: Boolean to indicate if the value should be converted into a human readible format (e.g. Network instead of N)
    
    Returns:
        dict: Mapping of Token key to value (e.g. AV=Network)
    '''
    # Mapping for CVSS 3.x metrics and their possible values
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
        raise TypeError(f"Only CVSS3 can be tokenized {vector_string}")

    # Clean the string
    vector = vector_string.strip()
    if "/" in vector and ("CVSS:3.0" in vector or "CVSS:3.1" in vector):
        vector = vector.split("/", 1)[1]

    readable_components = {}
    
    try:
        for part in vector.split("/"):
            if not part: continue
            key, val = part.split(":")
            if human_readible:
                human_value = CVSS_MAP.get(key, {}).get(val, val)
            else:
                human_value = val
            
            readable_components[key] = human_value
            
        return readable_components
    except ValueError:
        raise ValueError(f"Invalid CVSS format: {vector_string}")

def get_component_list(file:str, type:str, csv_column_id):
    cpe_list=[]

    if type.lower() == "csv":
        with open(file, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            # Iterate over each CPE within the BOM
            for row in reader:
                cpe_list.append(row[csv_column_id].strip())

    else:
        # Load the CycloneDX JSON file
        with open(file, 'r') as f:
            json_data = json.load(f)
        bom = Bom.from_json(data=json_data)
        cpe_list = []
        for component in bom.components:
            if component.cpe:
                cpe_list.append(str(component.cpe))
            elif component.purl:
                cpe_list.append(str(component.purl))
    
    return cpe_list

def populate_template_sheet(new_sheet, data_row, config, bom_name, component_id, vuln_id, vuln_desc, pub_date, vector_str, base_score, is_kev):
    if hasattr(config, "column_id_bom"):
        new_sheet.cell(row=data_row, column=config.column_id_bom).value = bom_name
    if hasattr(config, "column_id_cpe"):
        new_sheet.cell(row=data_row, column=config.column_id_cpe).value = component_id
    if hasattr(config, "column_id_cve"):
        new_sheet.cell(row=data_row, column=config.column_id_cve).value = vuln_id
    if hasattr(config,"template_max_description_char") and len(vuln_desc) > config.template_max_description_char:
        new_sheet.cell(row=data_row, column=config.column_id_description).value = f"{vuln_desc[:config.template_max_description_char]} (truncated)"
    else:
        new_sheet.cell(row=data_row, column=config.column_id_description).value = vuln_desc
    if hasattr(config, "column_id_publish_date"):
        new_sheet.cell(row=data_row, column=config.column_id_publish_date).value = pub_date[:10]
    if hasattr(config, "column_id_cvss"):
        new_sheet.cell(row=data_row, column=config.column_id_cvss).value = vector_str
    if hasattr(config, "column_id_base_score"):
        new_sheet.cell(row=data_row, column=config.column_id_base_score).value = base_score
    if hasattr(config, "column_id_is_kev"):
        new_sheet.cell(row=data_row, column=config.column_id_is_kev).value = is_kev

    if hasattr(config,"split_cvss_score") and config.split_cvss_score:
        try:
            cvss_tokens = tokenize_cvss3_human(vector_str)
            if hasattr(config, "column_split_cvss_av"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_av).value = cvss_tokens['AV']
            if hasattr(config, "column_split_cvss_ac"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_ac).value = cvss_tokens['AC']
            if hasattr(config, "column_split_cvss_pr"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_pr).value = cvss_tokens['PR']
            if hasattr(config, "column_split_cvss_ui"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_ui).value = cvss_tokens['UI']
            if hasattr(config, "column_split_cvss_s"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_s).value = cvss_tokens['S']
            if hasattr(config, "column_split_cvss_c"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_c).value = cvss_tokens['C']
            if hasattr(config, "column_split_cvss_i"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_i).value = cvss_tokens['I']
            if hasattr(config, "column_split_cvss_a"):
                new_sheet.cell(row=data_row, column=config.column_split_cvss_a).value = cvss_tokens['A']
        except TypeError as e:
            print(f"Invalid CVSS type, {e}")

def populate_epss_data(new_sheet, config, epss_manager):
    if hasattr(config, "column_id_epss"):
        for cve, epss_score, idx in epss_manager:
            new_sheet.cell(row=idx, column=config.column_id_epss).value = epss_score
 
def copy_data_validations(source_ws, dest_ws):
    '''
    openpyxl does not copy data validations when a new worksheet is cloned. This method
    will copy the data validations from the source WS to the destination workshee. Currently
    formatting is carried over, just not validation.

    Args:
        source_ws: Source Worksheet to clone from
        dest_ws Destination worksheet to clone into
    
    '''
    for dv in source_ws.data_validations.dataValidation:
        new_dv = copy.copy(dv)
        dest_ws.add_data_validation(new_dv)

def apply_formatting_to_range(worksheet, source_row_idx, start_row, count):
    """
    Clones the formatting and data validation rules from one cell within a spreadsheet to the rest
    within the same column.

    Args:
        dest_ws: Worksheet that contains both the source and the destination cells to clone
        source_row_idx: The 1-based_index row that contains the formatting and rules to clone
        start_row: The row where the clone should start from (this needs to be higher than the source row)
        count: Number of data rows to clone formatting for
    """
    max_col = worksheet.max_column

    # Simple edge case check
    if start_row <= source_row_idx:
        return

    # Capture the styles from the source row once
    row_styles = []
    for col in range(1, max_col + 1):
        cell = worksheet.cell(row=source_row_idx, column=col)
        # Store a dictionary of the style objects
        style_dict = {
            'font': copy.copy(cell.font),
            'border': copy.copy(cell.border),
            'fill': copy.copy(cell.fill),
            'number_format': cell.number_format,
            'protection': copy.copy(cell.protection),
            'alignment': copy.copy(cell.alignment)
        }
        row_styles.append(style_dict)

    # Apply styles to the target range
    for r_idx in range(start_row, start_row + count):
        for c_idx in range(1, max_col + 1):
            target_cell = worksheet.cell(row=r_idx, column=c_idx)
            s = row_styles[c_idx - 1]
            
            target_cell.font = s['font']
            target_cell.border = s['border']
            target_cell.fill = s['fill']
            target_cell.number_format = s['number_format']
            target_cell.protection = s['protection']
            target_cell.alignment = s['alignment']

def apply_data_validation_rules(worksheet, source_row_idx, count):
    max_col = worksheet.max_column

    # Update Data Validations (Drop-downs)
    for c in range(1, max_col + 1):
        column_letter = get_column_letter(c)
        source_cell_column_id = f"{column_letter}{source_row_idx}"
        target_cell_column_id = f"{column_letter}{source_row_idx+count}"
        target_range = f"{source_cell_column_id}:{target_cell_column_id}"

        target_dv = None
        for dv in worksheet.data_validations.dataValidation:
            for r in dv.ranges:
                range_string = r.coord
                if ":" not in range_string:
                    range_string = f"{range_string}:{range_string}"
                
                min_col, min_row, max_col, max_row = range_boundaries(range_string)
                if (min_col <= c <= max_col) and (min_row <= source_row_idx <= max_row):
                    target_dv = dv
                    break
            if target_dv: break

        if target_dv:
            target_dv.ranges.add(target_range)

def apply_static_content(config, source, destination, start_row, count):
    static_cols=1
    while hasattr(config,f"column_static_{static_cols}_id"):
        static_col_id = getattr(config,f"column_static_{static_cols}_id")
        
        if hasattr(config,f"column_static_{static_cols}_value"):
            static_val = str(getattr(config,f"column_static_{static_cols}_value"))
            for row in range(start_row, start_row + count, 1):
                destination.cell(row=row, column=static_col_id).value = static_val.replace("{row}",f"{row}")

        else:
            formula_string = source.cell(row=start_row, column=static_col_id).value
            origin_cell_str = f"{get_column_letter(static_col_id)}{start_row}"
            for row in range(start_row, start_row + count, 1):
                new_cell_str = f"{get_column_letter(static_col_id)}{row}"
                destination.cell(row=row, column=static_col_id).value = Translator(formula_string, origin=origin_cell_str).translate_formula(new_cell_str)

        static_cols=static_cols+1

def valid_date(s):
    """Custom type for argparse to validate YYYY-MM-DD format."""
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        msg = f"Not a valid date: '{s}'. Expected format: YYYY-MM-DD."
        raise argparse.ArgumentTypeError(msg)

def main():
    parser = argparse.ArgumentParser(
        description="Application to scan the NVD database for CVE's associated to specific CPE inputs, and provide data for analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--config", type=str, required=False, help="Path to the .ini configuration file")
    parser.add_argument("--load", type=str, required=False, help="Load a pre-existing JSON dump for testing purposes")
    parser.add_argument("--dump", action='store_true', required=False, help="Dump the last JSON object downloaded")
    parser.add_argument("--outdir", type=str, required=False, help="Output directory for the generated file")
    parser.add_argument("--system_override", type=str, required=False, help="System.ini file to use in place of the defined value in the configuration file")
    # Adding the date arguments
    parser.add_argument("--start", help="The start date - format YYYY-MM-DD", type=valid_date)
    parser.add_argument("--end", help="The end date - format YYYY-MM-DD", type=valid_date, default=datetime.now()) # Optional: defaults to today if not provided)
    args = parser.parse_args()

    config = None
    if args.config:
            if os.path.exists(args.config):
                config = nvdconfig.NVDConfigFile(args.config)

    if config is None:
        config = nvdconfig.NVDConfigFile('config.ini')

    validate_certificates = True
    if hasattr(config.GLOBAL,"validate_remote_certificate"):
        validate_certificates = config.GLOBAL.validate_remote_certificate

    if hasattr(config.GLOBAL, "score_system_ver"):
        nvd_obj=nvd.NVD(config.NVD.api_key, validate_certificates, config.GLOBAL.score_system_ver)
    else:
        nvd_obj=nvd.NVD(config.NVD.api_key, validate_certificates)

    osv_obj=osv.OSV(20, validate_certificates)
    kev_obj=cisa.KEV(validate_certificates)
    kev_obj.load_kevs()

    template_file=Path(config.TEMPLATE.template).resolve()
    if not os.path.exists(template_file):
        raise FileNotFoundError(f"The file {template_file} does not exist")

    current_query_count=0
    combine_sboms=False
    include_zero_counts=False
    include_deferred_vulns=False

    if hasattr(config.GLOBAL,"include_zero_vuln_components"):
        include_zero_counts = config.GLOBAL.include_zero_vuln_components
    if hasattr(config.GLOBAL,"ignore_defferred"):
        include_deferred_vulns = not config.GLOBAL.ignore_defferred

    system_configs=None
    if args.system_override:
        system_configs = [args.system_override]
    else:
        system_configs = config.GLOBAL.input_configs

    # Run through each system configuration in the global list
    for system in system_configs:
        system_config = nvdconfig.SystemConfigFile(system)
        clean_system_name=system_config.name[:31]
        print(f"System: {system} / {clean_system_name}")

        if hasattr(system_config,"combine_all_boms"):
            combine_sboms = system_config.combine_all_boms

        wb = load_workbook(filename=template_file, keep_vba=True)
        if hasattr(config.TEMPLATE,"template_sheet_name"):
            template_name = config.TEMPLATE.template_sheet_name
        else:
            template_name = wb.sheetnames[0]
        
        template_sheet = wb[template_name]
        template_root_name, template_ext = os.path.splitext(template_file)
        new_sheet = None

        # If everything is being combined, don't duplicate sheets
        if combine_sboms:
            new_sheet = template_sheet

        row_count=0
        data_row = config.TEMPLATE.template_start_row

        # For each system parse the list of BOMs to scan. Each BOM gets a unique sheet within the outputed excel file
        for bom in system_config.boms:
            print(f"BOM: {bom}")
            clean_name=Path(bom).stem[:31]

            if not combine_sboms:
                new_sheet = wb.copy_worksheet(template_sheet)
                # Check if the source has an auto-filter, and clone that over as well
                if template_sheet.auto_filter.ref:
                    new_sheet.auto_filter.ref = template_sheet.auto_filter.ref
                copy_data_validations(template_sheet, new_sheet)
                data_row = config.TEMPLATE.template_start_row
                row_count = 0
                new_sheet.title = f"RA_{clean_name}"

            csv_column_id = 0
            if hasattr(system_config, "bom_cpe_column"):
                csv_column_id=system_config.bom_cpe_column
            component_list = get_component_list(bom, system_config.bom_format, csv_column_id)

            for component_id in component_list:
                print(f"Analyzing Component: {component_id}")

                if args.load:
                    print(f"Loading {args.load} instead of NVD Scan")
                    with open(args.load) as j:
                        obj_json = json.load(j)
                else:
                    # Limit the number of scans we do before a delay is initiated.
                    if current_query_count >= config.RATE_LIMITER.requests_per_delay:
                        time.sleep(config.RATE_LIMTER.request_delay)
                        current_query_count=0

                    # If it is a CPE, then use NVD as the source of vulnerabilities
                    if component_id.startswith("cpe:"):
                        print(f"Scanning for CPE Information: {component_id}")
                        obj_json = nvd_obj.query_for_vulnerabilities(component_id)

                        if args.dump:
                            with open('vulnerability_dump.json', 'w') as f:
                                json.dump(obj_json, f, indent=4)   

                        if obj_json["totalResults"] > 0:
                            epss_data = epss.EPSS()

                            for vuln in obj_json['vulnerabilities']:
                                cve_id, pub_date, cve_desc, cve_status, base_score, vector_st = nvd_obj.tokenize_cve(vuln['cve'])
                                #print(f"{component_id} | {cve_id} | {pub_date} | {cve_status} | Score: {base_score} | {vector_st} | {cve_desc[:50]}...")

                                pub_dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).replace(tzinfo=None)
                                is_after_start = True
                                is_before_end = True

                                if args.start:
                                    is_after_start = pub_dt >= args.start
                                if args.end:
                                    is_before_end = pub_dt <= args.end

                                is_kev = kev_obj.query_cpe(cve_id)
                                if not include_deferred_vulns or cve_status.lower() == "deferred":
                                    if is_after_start and is_before_end:
                                        epss_data.register_cve(cve_id=cve_id, indexer_id=data_row)
                                        populate_template_sheet(new_sheet, data_row, config.TEMPLATE, clean_name, component_id, cve_id, cve_desc, pub_date, vector_st, base_score, is_kev)
                                        data_row=data_row+1
                                        row_count=row_count+1

                            # After the scanning is done, pull the EPSS data. This is done in bulk to save time and API calls
                            epss_data.query()
                            populate_epss_data(new_sheet, config.TEMPLATE, epss_data)


                        else:
                            print(f"No Vulnerabilities Found | {component_id} ")
                            if include_zero_counts:
                                populate_template_sheet(new_sheet, data_row, config.TEMPLATE, clean_name, component_id, 'None', 'No Vulnerabilities Found', '0/0/0 00:00:00', 'N/A', 0, False)
                                data_row=data_row+1
                                row_count=row_count+1


                    # If it is a PURL then use Googles OSV as the source of vulnerabilities
                    elif component_id.startswith("pkg:"):
                        print(f"Scanning for PURL Information: {component_id}")
                        obj_json = osv_obj.query_for_vulnerabilities(component_id)

                        if args.dump:
                            with open('vulnerability_dump.json', 'w') as f:
                                json.dump(obj_json, f, indent=4)   

                        if 'vulns' in obj_json:
                            for vuln in obj_json['vulns']:
                                cve_id, pub_date, cve_desc, cve_status, base_score, vector_st = osv.OSV.tokenize_vuln(vuln)

                                pub_dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).replace(tzinfo=None)
                                is_after_start = True
                                is_before_end = True

                                if args.start:
                                    is_after_start = pub_dt >= args.start
                                if args.end:
                                    is_before_end = pub_dt <= args.end
                                
                                if is_after_start and is_before_end:
                                    is_kev = False
                                    populate_template_sheet(new_sheet, data_row, config.TEMPLATE, clean_name, component_id, cve_id, cve_desc, pub_date, vector_st, base_score, is_kev)
                                    data_row=data_row+1
                                    row_count=row_count+1
                                
                        else:
                            print(f"No Vulnerabilities Found | {component_id} ")
                            if include_zero_counts:
                                populate_template_sheet(new_sheet, data_row, config.TEMPLATE, clean_name, component_id, 'None', 'No Vulnerabilities Found', '0/0/0 00:00:00', 'N/A', 0, False)
                                data_row=data_row+1
                                row_count=row_count+1

            # If each BOM is seperate, then format once the sheet is done
            if not combine_sboms:
                apply_static_content(config.TEMPLATE, template_sheet, new_sheet, config.TEMPLATE.template_start_row, row_count)
                apply_formatting_to_range(new_sheet, config.TEMPLATE.template_start_row, config.TEMPLATE.template_start_row + 1, row_count - 1)
                apply_data_validation_rules(new_sheet, config.TEMPLATE.template_start_row, row_count)

        # If we had combined all the SBOMs, then to avoid over formmating just do it once after the entire list is complete
        if combine_sboms:
            apply_static_content(config.TEMPLATE, template_sheet, new_sheet, config.TEMPLATE.template_start_row, row_count)
            apply_formatting_to_range(new_sheet, config.TEMPLATE.template_start_row, config.TEMPLATE.template_start_row + 1, row_count - 1)
            apply_data_validation_rules(new_sheet, config.TEMPLATE.template_start_row, row_count)

        if not combine_sboms:
            wb.remove(wb[template_name])
            
        if args.outdir:
            wb.save(f"{args.outdir}/{clean_system_name}{template_ext}")
        else:
            wb.save(f"{clean_system_name}{template_ext}")


if __name__ == "__main__":
    main()

