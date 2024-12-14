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

1. Run the script:

    ```sh
    python ipf-nmap-ip.py
    ```

2. The script will:
    - Initialize the IP Fabric client.
    - Retrieve managed IP addresses from IP Fabric.
    - Filter out private IP addresses.
    - Scan the public IP addresses for a specified port (default is port 22).
    - Save the scan results to a CSV file with a timestamped filename.

## Configuration

- You can change the port to be scanned by modifying the `port_to_check` variable in the `main` function.

## Logging

- The script uses the `loguru` library for logging. Logs will be printed to the console.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
