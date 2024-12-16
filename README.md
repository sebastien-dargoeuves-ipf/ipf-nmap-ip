# IPF IP Nmap Scanner

This project is a Python script that scans IP addresses using Nmap and saves the results to a CSV file. It leverages the IP Fabric API to retrieve managed IP addresses and filters out private IP addresses.

## Prerequisites

- Python 3.9+
- IP Fabric account and API token

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

3. Create a `.env` file in the project directory with the following variables:

    ```env
    IPF_URL=https://your-ipfabric-instance.com
    IPF_TOKEN=your_ipf_api_token
    IPF_VERIFY=True
    IPF_SNAPSHOT_ID=$last
    ```

## Usage

1. Collect IP addresses from IP Fabric:

    ```sh
    python ipf-nmap-ip.py collect --output collected_ips.csv --public
    ```

    - `--output` (optional): Name of the file to output the list of IPs to scan.
    - `--public` (optional): Only collect public IP addresses from IP Fabric.

2. Scan the collected IP addresses:

    ```sh
    python ipf-nmap-ip.py scan --input collected_ips.csv --output scan_results.csv
    ```

    - `--input` (optional): Name of the file containing the IP addresses to scan.
    - `--output` (optional): Name of the file to output the scan results.

    If no `--input` is provided, the script will ask you to select a file from the `collected_ips` directory.

3. Collect AND scan IP addresses in one step:

    ```sh
    python ipf-nmap-ip.py all --output scan_results.csv --public
    #or
    python ipf-nmap-ip.py all
    ```

    - `--output` (optional): Name of the file to output the scan results.
    - `--public` (optional): Only collect public IP addresses from IP Fabric.

## Configuration

- You can change the port(s) to be scanned by modifying the `NMAP_PORTS` variable in the `settings.py` file or by setting the `NMAP_PORTS` environment variable. It has to be a string in the format `22-23,80,443`.

## Logging

- The script uses the `loguru` library for logging. Logs will be printed to the console and saved to a log file in the `logs` directory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
