import argparse
import openpyxl

def update_excel_data(source_path, dest_path, match_col, columns, match_col_idx):
    """
    Synchronizes specific columns between Excel files by matching row keys.
    
    Args:
        source_path (str):
        dest_path (str):
        match_col (str):
        columns (list):
        match_col_idx (str):
    """
    # Load workbooks
    wb_src = openpyxl.load_workbook(source_path, data_only=True)
    wb_dst = openpyxl.load_workbook(dest_path)
    
    ws_src = wb_src.active
    ws_dst = wb_dst.active

    # Create a mapping of {match_value: row_index} for the destination file
    # This makes the matching process significantly faster (O(n) vs O(n^2))
    dst_map = {}
    for row in range(1, ws_dst.max_row + 1):
        key = ws_dst[f"{match_col_idx}{row}"].value
        if key is not None:
            dst_map[key] = row

    # Iterate through source rows and update destination if key exists
    updated_count = 0
    for row in range(1, ws_src.max_row + 1):
        key = ws_src[f"{match_col_idx}{row}"].value
        
        if key in dst_map:
            dest_row = dst_map[key]
            for col in columns:
                val = ws_src[f"{col}{row}"].value
                ws_dst[f"{col}{dest_row}"] = val
            updated_count += 1
    
    wb_dst.save(dest_path)
    print(f"Successfully synced {updated_count} rows to {dest_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Excel columns row-by-row.")
    parser.add_argument("--source", required=True, help="Original risk assessment containing previous answers and content")
    parser.add_argument("--destination", required=True, help="New excel file containing old and new vulnerabilities")
    parser.add_argument("--columns", nargs='+', required=True, help="List of columns to copy from source to destination if a match is found")
    parser.add_argument("--match", dest="match_col_idx", required=True, help="Column letter to use as the matching key")

    args = parser.parse_args()
    update_excel_data(args.source, args.destination, None, args.columns, args.match_col_idx)
