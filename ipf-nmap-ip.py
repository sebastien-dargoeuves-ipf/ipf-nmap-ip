import os

import typer
from ipfabric import IPFClient
from loguru import logger

from modules.settings import Settings
from modules.utils import (
    export_to_csv,
    ip_is_public,
    read_file,
    scan_nmap_ip_addresses,
    select_file,
)

settings = Settings()
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


@app.callback()
def logging_configuration():
    """
    Configures logging settings for the script execution.

    Args:
        None

    Returns:
        None
    """
    root_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_dir = os.path.join(root_dir, "logs")
    os.makedirs(default_log_dir, exist_ok=True)
    log_file_path = os.path.join(default_log_dir, "log_file.log")
    logger.add(
        log_file_path,
        retention="180 days",
        rotation="1 MB",
        level="INFO",
        compression="tar.gz",
    )
    logger.info("---- NEW EXECUTION OF SCRIPT ----")


@app.command("collect", help="Collect IP addresses from IP Fabric's Managed IP table.")
def collect_ips(
    collected_ip_file: str = typer.Option(
        settings.COLLECTED_IP_FILENAME,
        "-o",
        "--output",
        help="Name of the file to output the list of IPs to scan",
    ),
    only_public_ip: bool = typer.Option(
        False,
        "--public",
        "-pub",
        help="Only collect public IP addresses from IP Fabric",
    ),
):
    """
    Collect IP addresses from IP Fabric's Managed IP table.

    This function retrieves managed IP addresses from IP Fabric, with optional filtering for public IPs.
    It exports the collected IP addresses to a CSV file for further processing.

    Args:
        collected_ip_file (str, optional): Name of the file to output the list of IPs to scan.
            Defaults to settings.COLLECTED_IP_FILENAME.
        only_public_ip (bool, optional): Flag to collect only public IP addresses. Defaults to False.

    Returns:
        str: Path to the generated CSV file containing collected IP addresses.
    """

    logger.info("Initializing IPFClient")
    ipf = IPFClient(
        base_url=settings.IPF_URL,
        auth=settings.IPF_TOKEN,
        verify=settings.IPF_VERIFY,
        snapshot_id=settings.IPF_SNAPSHOT_ID,
    )

    ip_filter = {
        "ip": [
            "nreg",
            settings.IP_EXCLUDE_FILTER,
        ]
    }

    all_managed_ips = ipf.technology.addressing.managed_ip_ipv4.all(filters=ip_filter)
    if only_public_ip:
        ip_list = [
            {"IP": ip["ip"], "Device": ip["hostname"], "Interface": ip["intName"]}
            for ip in all_managed_ips
            if ip_is_public(ip["ip"])
        ]
        logger.info(f"Found {len(ip_list)} public IPs after applying the filter: {settings.IP_EXCLUDE_FILTER}")
    else:
        ip_list = [{"IP": ip["ip"], "Device": ip["hostname"], "Interface": ip["intName"]} for ip in all_managed_ips]
        logger.info(f"Found {len(ip_list)} IPs after applying the filter: {settings.IP_EXCLUDE_FILTER}")
    if collected_ip_file := export_to_csv(ip_list, collected_ip_file, settings.COLLECTED_IP_FOLDER):
        logger.success(f"Collected IPs saved to {collected_ip_file}")
        return collected_ip_file


@app.command("scan", help="Scan IP addresses using nmap.")
def scan_ips(
    collected_ip_file: typer.FileText = typer.Option(
        None,
        "-i",
        "--input",
        help="Name of the file containing the IP addresses to scan",
    ),
    scan_result_file: str = typer.Option(
        None,
        "-o",
        "--output",
        help="Name of the file to output the scan results",
    ),
):
    """
    Scan IP addresses using nmap.

    This function performs network scanning on a list of IP addresses using nmap. It allows users to specify input and output files for IP scanning and results.

    The function handles file selection if no input file is provided, reads IP addresses, performs nmap scanning, and exports the results to a CSV file.

    Args:
        collected_ip_file (typer.FileText, optional): File containing IP addresses to scan.
            If not provided, a file will be interactively selected.
        scan_result_file (str, optional): Name of the file to output scan results.
            If not provided, a default name will be generated.

    Returns:
        str: Path to the generated CSV file containing nmap scan results.
    """

    if not collected_ip_file:
        collected_ip_file = select_file(settings.COLLECTED_IP_FOLDER)
    if not scan_result_file:
        scan_result_file = collected_ip_file.name.split("/")[-1]
    ips_to_scan = read_file(collected_ip_file)
    scan_results = scan_nmap_ip_addresses(ips_to_scan, settings.NMAP_PORTS)
    if scan_result_file := export_to_csv(scan_results, scan_result_file, settings.SCAN_RESULT_FOLDER):
        logger.success(f"Scan results saved to {scan_result_file}")
        return scan_result_file


@app.command("all", help="Collect IP addresses from IP Fabric's Managed IP table.")
def collect_and_scan(
    only_public_ip: bool = typer.Option(
        False,
        "--public",
        "-pub",
        help="Only collect public IP addresses from IP Fabric",
    ),
    scan_result_file: str = typer.Option(
        settings.SCAN_RESULT_FILENAME,
        "-o",
        "--output",
        help="Name of the file to output the scan results",
    ),
):
    """
    Collect and scan IP addresses from IP Fabric's Managed IP table.

    This function combines IP address collection and network scanning into a single workflow. It retrieves IP addresses from IP Fabric and then performs nmap scanning on the collected IPs.

    The function allows optional filtering for public IPs and provides flexibility in specifying the output scan results filename.

    Args:
        only_public_ip (bool, optional): Flag to collect only public IP addresses. Defaults to False.
        scan_result_file (str, optional): Name of the file to output scan results.
            Defaults to settings.SCAN_RESULT_FILENAME.

    Returns:
        None
    """

    collected_ip_file = collect_ips(settings.COLLECTED_IP_FILENAME, only_public_ip)
    with open(collected_ip_file, "r") as f:
        scan_ips(f, scan_result_file)


if __name__ == "__main__":
    app()
