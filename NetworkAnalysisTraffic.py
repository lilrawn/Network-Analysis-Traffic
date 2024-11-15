import tkinter as tk
from tkinter import messagebox
import socket
import nmap
import requests


# Function to get host information
def get_host_info(ip):
    try:
        # Checking if the host is online
        host = socket.gethostbyaddr(ip)
        return {"status": "Online", "hostname": host[0]}
    except socket.herror:
        return {"status": "Offline", "hostname": "Unknown"}


# Function to scan open ports
def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024', '-sS')
        open_ports = [
            port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open'
        ]
        return open_ports
    except Exception:
        return []


# Function to detect OS
def detect_os(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-O")
        os_info = nm[ip]['osmatch'][0]['name']
        return os_info
    except (KeyError, IndexError, Exception):
        return "Unknown"


# Function to get geolocation
def get_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "Unknown").split(",")
            return {
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "latitude": loc[0] if len(loc) > 1 else "Unknown",
                "longitude": loc[1] if len(loc) > 1 else "Unknown",
            }
    except Exception:
        pass
    return {
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "latitude": "Unknown",
        "longitude": "Unknown",
    }


# Function to check vulnerabilities (Mock function, replace with proper vulnerability checks)
def check_vulnerabilities(ip):
    # Placeholder for vulnerability checks.
    return ["Mock Vulnerability: Update software"]


# Main analysis function
def analyze_network(ip):
    host_info = get_host_info(ip)
    if host_info["status"] == "Offline":
        return {"status": "Offline"}

    open_ports = scan_ports(ip)
    os_info = detect_os(ip)
    geo_info = get_geolocation(ip)
    vulnerabilities = check_vulnerabilities(ip)

    return {
        "status": "Online",
        "hostname": host_info["hostname"],
        "os": os_info,
        "open_ports": open_ports,
        "location": geo_info,
        "vulnerabilities": vulnerabilities,
    }


# Function to handle the analysis process
def analyze():
    ip = ip_entry.get()
    if not ip:
        messagebox.showerror("Input Error", "Please enter a valid IP address.")
        return

    result = analyze_network(ip)

    if result["status"] == "Offline":
        result_text.set(f"The host at {ip} is offline.")
    else:
        result_message = f"""
        Hostname: {result['hostname']}
        OS: {result['os']}
        Open Ports: {', '.join(map(str, result['open_ports'])) if result['open_ports'] else "None"}
        Location: {result['location']['city']}, {result['location']['region']}, {result['location']['country']}
        Coordinates: {result['location']['latitude']}, {result['location']['longitude']}
        Vulnerabilities: {', '.join(result['vulnerabilities']) if result['vulnerabilities'] else "None"}
        """
        result_text.set(result_message.strip())


# GUI Setup
root = tk.Tk()
root.title("Network Analyzer")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

# IP Entry
ip_label = tk.Label(frame, text="Enter IP Address:")
ip_label.grid(row=0, column=0, sticky="w")

ip_entry = tk.Entry(frame, width=30)
ip_entry.grid(row=0, column=1, padx=10)

# Analyze Button
analyze_button = tk.Button(frame, text="Analyze", command=analyze)
analyze_button.grid(row=0, column=2)

# Result Display
result_text = tk.StringVar()
result_label = tk.Label(
    frame, textvariable=result_text, justify="left", anchor="w", wraplength=600
)
result_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(10, 0))

# Run the application
root.mainloop()
