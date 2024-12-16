import ipaddress
import json
import os
import sys
import time
from pathlib import Path
from typing import Union

import nmap3
import numpy as np
import pandas as pd
import typer
from loguru import logger
from rich.console import Console

try:
    from yaspin import yaspin
    from yaspin.spinners import Spinners

    YASPIN_ANIMATION = True
except ImportError:
    YASPIN_ANIMATION = False

console = Console()


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


def run_with_rich_spinner(task_name: str, task_func, *args, **kwargs):
    """
    Run a task with a spinner.

    Args:
        task_name: The name of the task.
        task_func: The function to run.
        *args: The arguments to pass to the function.
        **kwargs: The keyword arguments to pass to the function.

    Returns:
        The result of the task function.
    """
    logger.info(f"Running {task_name}...")
    start_time = time.time()
    with console.status(f"[bold yellow] {task_name}..."):
        result = task_func(*args, **kwargs)
    elapsed_time = time.time() - start_time
    # console.log(f"completed in {elapsed_time:.2f} seconds")
    logger.success(f"✅ {task_name} completed in {elapsed_time:.2f} seconds")
    return result


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


def scan_nmap_ip_addresses(ip_info_list: list, ports: str = "22"):
    """
    Scan IP addresses using nmap.

    Args:
        ip_info_list: A list of dictionaries containing IP addresses and related information.
        ports: The ports to scan, i.e., "22-23,80,443".

    Returns:
        A list of dictionaries containing the scan results.
    """
    nmap = nmap3.NmapScanTechniques()
    ip_string = " ".join(info["IP"] for info in ip_info_list)
    logger.info(f"Scanning IPs: {ip_string}")

    # I like to use yaspin for the spinner due to the timer, but it's optional, we can default to rich spinner
    if YASPIN_ANIMATION:
        spinner = yaspin(
            Spinners.bouncingBall,
            text="NMAP Scanner",
            timer=True,
        )
        spinner.start()
        scan_result = nmap.nmap_tcp_scan(
            ip_string, args=f"-p {ports} -Pn"
        )  # -Pn option to skip host discovery (no ping)
        spinner.ok("✅ ")
        logger.success(f"✅ NMAP Scanner completed in {spinner.elapsed_time:.2f} seconds")
    else:
        scan_result = run_with_rich_spinner(
            "NMAP Scanner", nmap.nmap_tcp_scan, ip_string, args=f"-p {ports} -Pn"
        )  # -Pn option to skip host discovery (no ping)

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
