Network Analyzer

A Python-based network analysis tool with a graphical user interface (GUI) that allows users to scan a given IP address.
The tool provides essential information about the target, including host status, open ports, operating system details, geolocation,
and potential vulnerabilities.

Features

Host Status: Check if the target IP is online or offline.
Hostname: Retrieve the hostname of the target system.
Operating System Detection: Identify the operating system running on the target.
Port Scanning: Scan open TCP ports in the range 1–1024.
Geolocation: Fetch the city, region, country, latitude, and longitude of the target using the IPInfo API.
Vulnerability Detection: A placeholder to display vulnerabilities (can be extended for real vulnerability scanning).
User-Friendly GUI: Built using Tkinter for easy interaction.

Technologies Used

Python: Core programming language.
Libraries:
  tkinter: For creating the graphical interface.
  socket: To check host status and hostname.
  python-nmap: A Python wrapper for Nmap for port and OS scanning.
  requests: To fetch geolocation data via an API.

Installation

1. Clone the Repository

git clone https://github.com/lilrawn/network-analyzer.git

cd network-analyzer

2. Install Dependencies
Ensure you have Python installed (version 3.7 or above), then run:

pip install python-nmap requests

4. Install Nmap

The tool relies on Nmap, which must be installed separately. Use one of the following commands based on your operating system:

Linux:

sudo apt install nmap

MacOS:

brew install nmap

Windows: Download and install Nmap from Nmap's official website.



Usage

1. Run the program:

python network_analyzer.py

2. Enter the target IP address in the provided input box.

3. Click Analyze to initiate the network scan.

4. View the following results displayed in the GUI:
  Host status (Online/Offline).
  Hostname.
  Open TCP ports.
  Detected operating system.
  Geolocation (city, region, country, coordinates).
  Detected vulnerabilities.


Screenshots

Input Screen
Results Screen

File Structure

network-analyzer/
├── network_analyzer.py  # Main script
├── README.md            # Project documentation
└── screenshots/         # Folder for screenshots


Extending the Tool

This tool is designed with modular functions to allow easy extension:
1. Vulnerabilities: Replace the check_vulnerabilities function with a real vulnerability database or API integration.
2. Advanced Port Scanning: Adjust the Nmap scan to include more ports or protocols.
3. Custom API: Replace ipinfo.io with another geolocation API if desired.


License

This project is licensed under the MIT License. See the LICENSE file for details.

Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description.

Acknowledgements

Nmap for their powerful network scanning tool.

IPInfo for providing geolocation API services.
