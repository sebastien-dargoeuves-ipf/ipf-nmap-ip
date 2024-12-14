import ipaddress
import json
import os
import sys
from  pathlib import Path
from typing import Union

import nmap
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


def scan_ip_addresses(ip_info_list, port):
    # Create a PortScanner object
    nm = nmap.PortScanner()
    results = []

    # Process IPs in batches of 5
    for i in range(0, len(ip_info_list), 5):
        batch = ip_info_list[i : i + 5]
        ip_string = " ".join(info["IP"] for info in batch)  # Extract IPs for the scan
        logger.info(f"Scanning batch {i + 1}-{i + len(batch)}: {ip_string}")

        try:
            # Perform the scan with -Pn option for the batch of IPs
            nm.scan(ip_string, str(port), arguments="-Pn")

            for info in batch:
                ip = info["IP"]
                # Initialize result for the current IP
                result = {
                    "IP": ip,
                    "Device": info["Device"],
                    "Interface": info["Interface"],
                    "Status": nm[ip].state(),
                    "Port": port,
                    "Port State": None,
                    "Reason": None,
                }

                # Check the state of the specified port
                if port in nm[ip]["tcp"]:
                    result["Port State"] = nm[ip]["tcp"][port]["state"]
                    result["Reason"] = nm[ip]["tcp"][port]["reason"]
                else:
                    result["Port State"] = "not found"
                    result["Reason"] = "Port not found in scan results."

                results.append(result)

        except Exception as e:
            logger.error(f"Error during scan for batch {ip_string}: {e}")
            results.extend(
                {
                    "IP": info["IP"],
                    "Device": info["Device"],
                    "Interface": info["Interface"],
                    "Status": "down",
                    "Port": port,
                    "Port State": "error",
                    "Reason": str(e),
                }
                for info in batch
            )
    return results
