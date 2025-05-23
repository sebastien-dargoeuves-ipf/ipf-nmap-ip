# IPF IP Nmap Scanner

This project is a Python script that scans IP addresses using Nmap and saves the results to a CSV file. It leverages the IP Fabric API to retrieve managed IP addresses and filters out private IP addresses.

## Prerequisites

- Python 3.9+
- IP Fabric account and API token
- Nmap installed on your system
- Python packages listed in the `requirements.txt` file:
  - ipfabric # matching you IP Fabric appliance version
  - loguru
  - pandas
  - python3-nmap
  - typer
  - yaspin # Optional for spinner

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/ipf-nmap-ip.git
    cd ipf-nmap-ip
    ```

2. Install the required Python packages:

    ```sh
    pip install -r requirements.txt
    ```

3. Create a `.env` file in the project directory with the following variables, you can copy the `.env.example` file and modify it:

    ```env
    IPF_URL=https://your-ipfabric-instance.com
    IPF_TOKEN=your_ipf_api_token
    IPF_VERIFY=True
    IPF_SNAPSHOT_ID=$last
    
    # IPs to exclude when collecting from IP Fabric
    IP_EXCLUDE_FILTER = "(^10\.)|(^172\.1[6-9])|(^172\.2[0-9])|(^172\.3[0-1])|(^192\.168)" # RFC1918

    # NMAP ports to scan
    NMAP_PORTS="22-23,80,443"
    ```

## Usage

1. Collect IP addresses from IP Fabric:

    ```sh
    # Collect IP addresses not matching the IP_EXCLUDE_FILTER
    python ipf-nmap-ip.py collect

    # Collect IP addresses not matching the IP_EXCLUDE_FILTER but only keep public IP addresses (based on ipaddress.is_global)
    python ipf-nmap-ip.py collect --public

    # Specify the output file
    python ipf-nmap-ip.py collect --output collected_ips.csv --public
    ```

    - `--output` (optional): Name of the file to output the list of IPs to scan.
    - `--public` (optional): Only keep public IP addresses from all IPs collected.

2. Scan the collected IP addresses:

    ```sh
    # Scan IP addresses from a file to be selected interactively, from the `collected_ips` directory
    python ipf-nmap-ip.py scan

    # Scan IP addresses from a file, output will match the input file name
    python ipf-nmap-ip.py scan --input collected_ips.csv

    # Scan IP addresses from a file and specify the output file
    python ipf-nmap-ip.py scan --input collected_ips.csv --output scan_results.csv
    ```

    - `--input` (optional): Name of the file containing the IP addresses to scan.
    - `--output` (optional): Name of the file to output the scan results.

    If no `--input` is provided, the script will ask you to select a file from the `collected_ips` directory.

3. Collect AND scan IP addresses in one step:

    ```sh
    # Collect IP addresses and scan them
    python ipf-nmap-ip.py all

    # Collect IP addresses and scan them, output will match the input file name
    python ipf-nmap-ip.py all --output scan_results.csv --public
    ```

    - `--output` (optional): Name of the file to output the scan results.
    - `--public` (optional): Only collect public IP addresses from IP Fabric.

## Configuration

- You can change the port(s) to be scanned by modifying the `NMAP_PORTS` variable in the `settings.py` file or by setting the `NMAP_PORTS` environment variable. It has to be a string in the format `22-23,80,443`.

## Working with an external source of information

To use this script to perform the nmap scanning, without using IP Fabric, you need to provide a csv file with the following columns:

- `IP`: The IP address to scan.
- `Device`: The device name (optional).
- `Interface`: The interface name (optional).

## Logging

- The script uses the `loguru` library for logging. Logs will be printed to the console and saved to a log file in the `logs` directory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
