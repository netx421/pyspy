import os
import socket
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping(host):
    with os.popen(f"ping -c 1 {host} 2>/dev/null") as f:
        if "1 received" in f.read():
            return host

def list_hosts(ip_address):
    base_ip = '.'.join(ip_address.split('.')[:-1])
    available_hosts = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(ping, f"{base_ip}.{i}") for i in range(1, 21)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                available_hosts.append(result)

    hostnames = {}
    for host in available_hosts:
        try:
            hostname = socket.gethostbyaddr(host)[0]
            hostnames[host] = hostname
        except socket.herror:
            hostnames[host] = host

    return hostnames

def port_scan(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        return port if result == 0 else None

def scan_ports(ip_address):
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(port_scan, ip_address, port) for port in range(1, 1001)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def check_suspicious_connections():
    suspicious_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED:
            local_address, local_port = conn.laddr
            remote_address, remote_port = conn.raddr
            if remote_port == 21:  # FTP port
                suspicious_connections.append(f"Suspicious FTP connection detected:\nLocal: {local_address}:{local_port}\nRemote: {remote_address}:{remote_port}")
            if remote_port == 22:  # SSH port
                suspicious_connections.append(f"Suspicious SSH connection detected:\nLocal: {local_address}:{local_port}\nRemote: {remote_address}:{remote_port}")
    return suspicious_connections

def display_banner():
    banner = r"""
██████╗ ██╗   ██╗     ███████╗██████╗ ██╗   ██╗
██╔══██╗╚██╗ ██╔╝     ██╔════╝██╔══██╗╚██╗ ██╔╝
██████╔╝ ╚████╔╝█████╗███████╗██████╔╝ ╚████╔╝ 
██╔═══╝   ╚██╔╝ ╚════╝╚════██║██╔═══╝   ╚██╔╝  
██║        ██║        ███████║██║        ██║   
╚═╝        ╚═╝        ╚══════╝╚═╝        ╚═╝   
    v 1.3 by x421
                                                                 
    """
    print(banner)

def main():
    display_banner()
    print("Welcome to PY-SEC - Secure Network Scanner")
    while True:
        print("\nMenu:")
        print("1. Discover hosts")
        print("2. Scan open ports")
        print("3. Check for suspicious connections")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            ip_address = input("Enter IP address to scan (e.g. 192.168.0.1): ")
            available_hosts = list_hosts(ip_address)
            if not available_hosts:
                print("No hosts available for scanning")
                continue
            print("Available hosts:")
            for i, host in enumerate(available_hosts):
                print(f"{i + 1}. {available_hosts[host]} ({host})")
        elif choice == '2':
            host_index = int(input("Enter host index to scan ports (0 to exit, -1 to scan all): "))
            if host_index == 0:
                break
            elif host_index == -1:
                for host in available_hosts:
                    open_ports = scan_ports(host)
                    if open_ports:
                        print(f"Open ports for {available_hosts[host]} ({host}):")
                        for port in open_ports:
                            print(f"  {port}")
                    else:
                        print(f"No open ports found for {available_hosts[host]} ({host})")
            elif host_index > 0 and host_index <= len(available_hosts):
                selected_host = list(available_hosts.keys())[host_index - 1]
                open_ports = scan_ports(selected_host)
                if open_ports:
                    print(f"Open ports for {available_hosts[selected_host]} ({selected_host}):")
                    for port in open_ports:
                        print(f"  {port}")
                else:
                    print(f"No open ports found for {available_hosts[selected_host]} ({selected_host})")  
            else:
                print("Invalid input")
        elif choice == '3':
            suspicious_connections = check_suspicious_connections()
            if suspicious_connections:
                for connection in suspicious_connections:
                    print(connection)
            else:
                print("No suspicious connections found.")
        elif choice == '4':
            print("Exiting PY-SEC. Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
