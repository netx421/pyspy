import psutil

# Function to check suspicious connections
def check_connections():
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

# Function to display the ASCII banner
def display_banner():
    banner = r"""
██████╗ ██╗   ██╗     ███████╗██████╗ ██╗   ██╗
██╔══██╗╚██╗ ██╔╝     ██╔════╝██╔══██╗╚██╗ ██╔╝
██████╔╝ ╚████╔╝█████╗███████╗██████╔╝ ╚████╔╝ 
██╔═══╝   ╚██╔╝ ╚════╝╚════██║██╔═══╝   ╚██╔╝  
██║        ██║        ███████║██║        ██║   
╚═╝        ╚═╝        ╚══════╝╚═╝        ╚═╝   
    v 1.1 by x421
                                                                 
    """
    print(banner)

# Main function
def main():
    display_banner()
    print("Welcome to PY-SPY - Detect Suspicious Network Connections")
    while True:
        print("\nMenu:")
        print("1. Check for suspicious connections")
        print("2. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            suspicious_connections = check_connections()
            if suspicious_connections:
                for connection in suspicious_connections:
                    print(connection)
            else:
                print("No suspicious connections found.")
        elif choice == '2':
            print("Exiting PY-SPY. Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

