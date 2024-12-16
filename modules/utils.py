import ipaddress
import json
import os
import sys
from  pathlib import Path
from typing import Union

import nmap3
import numpy as np
import pandas as pd
import typer
from loguru import logger

SCAN_RESULT_COLUMNS = [
    "IP",
    "-",
    "Device",
    "Interface",
    "|",
    "Status",
    "Port"
    "Port State",
    "Reason",
]

def ip_is_valid(ip):
    """Check if the given IP address is valid."""
    try:
        ipaddress.ip_address(ip)
        return True  # Return True if it's valid
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return False  # Invalid IP addresses are treated as non-valid

def ip_is_public(ip):
    """Check if the given IP address is public."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global  # Return True if it's public
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return False  # Invalid IP addresses are treated as non-public

def file_to_json(input: typer.FileText) -> json:
    try:
        output = json.load(input)
    except Exception as e:
        logger.error(f"Error loading file `{input}`, not a valid json. Error: {e}")
        sys.exit()
    return output


def export_to_csv(list, filename, output_folder) -> bool:
    """
    Exports a list of dictionaries to a CSV file using pandas, logs a message using the logger, and returns the resulting DataFrame.

    Args:
        list: A list of dictionaries to be exported.
        filename: The name of the CSV file to be created.
        output_folder: Location where the file will be saved.

    Returns:
        Boolean indicating if the file was saved successfully.
    """
    timestamp = pd.Timestamp.now().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"{timestamp}_{filename}"

    if not list:
        logger.warning(f"No data to export in the file `{filename}`")
        return False
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    output_file = Path(f"{output_folder}/{filename}")
    try:
        result = pd.DataFrame(list)
        result.to_csv(output_file, index=False)
        # output_file = Path(output_file)
        logger.info(f"File `{output_file.absolute()}` saved")
        return output_file
    except Exception as e:
        logger.error(f"Error saving file `{output_file}`. Error: {e}")
        return False


def read_file(filename) -> Union[dict, bool]:
    """
    Reads a CSV/XLSX file using pandas and returns the resulting DataFrame.

    Args:
        filename: The name of the CSV/XLSX file to be read.

    Returns:
        A pandas DataFrame representing the data in the CSV/XLSX file.
    """
    try:
        if filename.name.endswith(".csv"):
            df = pd.read_csv(filename.name)
            df.replace({np.nan: None}, inplace=True)
        elif filename.name.endswith(".xlsx"):
            df = pd.read_excel(filename.name)
            df.replace({np.nan: None}, inplace=True)
        else:
            logger.error(f"Invalid file format for file `{filename.name}`. Please provide a CSV or Excel file.")
            sys.exit()
    except Exception as e:
        logger.error(f"Error reading file `{filename}`. Error: {e}")
        sys.exit()
    try:
        result = df.to_dict(orient="records")
        logger.info(f"File `{filename.name}` loaded ({len(df)} entries)")
        return result
    except Exception as e:
        logger.error(f"Error transforming file `{filename}` to dict. Error: {e}")
        sys.exit()


# def scan_nmap_ip_addresses_batches(ip_info_list, port):
#     # Create a PortScanner object
#     nm = nmap.PortScanner()
#     nmap = nmap3.NmapScanTechniques()
#     result = nmap.nmap_tcp_scan(TARGET, args="-p 22")
#     results = []

#     # Process IPs in batches of 5
#     for i in range(0, len(ip_info_list), 5):
#         batch = ip_info_list[i : i + 5]
#         ip_string = " ".join(info["IP"] for info in batch)  # Extract IPs for the scan
#         logger.info(f"Scanning batch {i + 1}-{i + len(batch)}: {ip_string}")

#         try:
#             # Perform the scan with -Pn option for the batch of IPs
#             nm.scan(ip_string, str(port), arguments="-Pn")

#             for info in batch:
#                 ip = info["IP"]
#                 # Initialize result for the current IP
#                 result = {
#                     "IP": ip,
#                     "Device": info["Device"],
#                     "Interface": info["Interface"],
#                     "Status": nm[ip].state(),
#                     "Port": port,
#                     "Port State": None,
#                     "Reason": None,
#                 }

#                 # Check the state of the specified port
#                 if port in nm[ip]["tcp"]:
#                     result["Port State"] = nm[ip]["tcp"][port]["state"]
#                     result["Reason"] = nm[ip]["tcp"][port]["reason"]
#                 else:
#                     result["Port State"] = "not found"
#                     result["Reason"] = "Port not found in scan results."

#                 results.append(result)

#         except Exception as e:
#             logger.error(f"Error during scan for batch {ip_string}: {e}")
#             results.extend(
#                 {
#                     "IP": info["IP"],
#                     "Device": info["Device"],
#                     "Interface": info["Interface"],
#                     "Status": "down",
#                     "Port": port,
#                     "Port State": "error",
#                     "Reason": str(e),
#                 }
#                 for info in batch
#             )
#     return results


def scan_nmap_ip_addresses(ip_info_list: list, port: str = "22"):
    # Create a PortScanner object
    nmap = nmap3.NmapScanTechniques()
    ip_string = " ".join(info["IP"] for info in ip_info_list)  # Extract IPs for the scan
    scan_result = nmap.nmap_tcp_scan(ip_string, args=f"-p {port} -Pn") # -Pn option to skip host discovery (no ping)
    output = []
    for info in ip_info_list:
        ip = info["IP"]
        # Initialize result for the current IP
        for result_port in scan_result[ip]["ports"]:
            result = {
                "IP": ip,
                "Device": info["Device"],
                "Interface": info["Interface"],
                "Protocol": result_port["protocol"],
                "Port": result_port["portid"],
                "Port State": result_port["state"],
                "PortReason": result_port["reason"],
                # "State": scan_result[ip]["state"]["state"],
                # "Reason": scan_result[ip]["state"]["reason"],
            }

            output.append(result)

    return output


def select_file(folder: str):
    # # Get the list of files in the folders
    file_list = []
    for root, dirs, files in os.walk(folder):
        file_list.extend(os.path.join(root, file) for file in files)
    if not file_list:
        logger.warning(f"No files found in the '{folder}' folder, nothing to restore.")
        return False
    # Display the list of files with corresponding numbers
    print(f"List of files in the '{folder}' folder:")
    for i, filename in enumerate(file_list):
        print(f"{i+1}. {filename}")

    while True:
        # Prompt for file selection
        selection = typer.prompt("Enter the number corresponding to the file to read", type=int)

        # Check if the selected number is within range
        if 1 <= selection <= len(file_list):
            # Get the selected file name
            with open(file_list[selection - 1], "r") as f:
                file = f
            return file
        else:
            print("Selection outside the scope. Please select a valid number.")


# def select_folder(settings: Settings, unattended: bool = False, latest_backup_folder: str = None):
#     """
#     Select a JSON folder for restoration.

#     Args:
#         settings (Settings): The settings object containing the folder path.
#         unattended (bool): Flag indicating whether the selection should be done automatically without user interaction.

#     Returns:
#         List[str]: A list of file paths within the selected folder.
#     """
#     folder_list = []
#     for root, dirs, files in os.walk(settings.FOLDER_JSON):
#         folder_list.extend(
#             os.path.join(root, dir)
#             for dir in dirs
#             if dir.endswith(settings.FOLDER_JSON_ORIGINAL_SN)
#             or dir.endswith(settings.FOLDER_JSON_HOSTNAME)
#             or dir.endswith(settings.FOLDER_JSON_NEW_SN)
#         )
#     if not folder_list:
#         logger.warning(f"No files found in the '{settings.FOLDER_JSON}' folder, nothing to restore.")
#         return False

#     if unattended:
#         folder_name = latest_backup_folder
#     else:
#         print(f"List of folders in the `{settings.FOLDER_JSON}` directory:")
#         for i, folder_name in enumerate(folder_list):
#             print(f"{i+1}. {folder_name}")

#         while True:
#             # Prompt for file selection
#             selection = typer.prompt(
#                 "Enter the number corresponding to the Folder to restore (ideally use a `xxx/w_hostname` folder)",
#                 type=int,
#             )

#             # Check if the selected number is within range
#             if 1 <= selection <= len(folder_list):
#                 # Get the selected file name
#                 folder_name = folder_list[selection - 1]
#                 break
#             else:
#                 print("Selection outside the scope. Please select a valid number.")
#     return [os.path.join(folder_name, file) for file in os.listdir(folder_name)]

