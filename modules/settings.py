import os

from dotenv import find_dotenv, load_dotenv
from pydantic_settings import BaseSettings

load_dotenv(find_dotenv(), override=True)


class Settings(BaseSettings):
    """
    Represents the configuration settings for the site separation process.

    Explanation:
        This class defines the various settings required for the site separation process, such as IP Fabric URL,
        authentication token, ServiceNow credentials, and other related parameters.
    """

    IPF_URL: str = os.getenv("IPF_URL")
    IPF_TOKEN: str = os.getenv("IPF_TOKEN")
    IPF_SNAPSHOT_ID: str = os.getenv("IPF_SNAPSHOT_ID", "$last")
    IPF_VERIFY: bool = eval(os.getenv("IPF_VERIFY", "False").title())
    IPF_TIMEOUT: int = os.getenv("IPF_TIMEOUT", 60)

    # Regex pattern to exclude private IP addresses RFC1918
    IP_EXCLUDE_FILTER: str = os.getenv("IP_EXCLUDE_FILTER", "^(10\.|172\.(1[6-9]|2[0-9]|3[01])|192\.168\.)")
    # NMAP Port
    NMAP_PORT: int = os.getenv("NMAP_PORT", 22)

    # Output folder & files
    OUTPUT_FOLDER: str = "output"
    COLLECTED_IP_FILENAME: str = "collected_ips.csv"
    SCAN_RESULT_FILENAME: str = "ip_scan_results.csv"
