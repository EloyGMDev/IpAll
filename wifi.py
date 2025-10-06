import socket
import time
import ipaddress
import webbrowser
from concurrent.futures import ThreadPoolExecutor

WIFI_PASSWORD_MOCK = "yes" 
SCAN_PORTS_LIST = [] 
TIMEOUT_SECONDS = 0.5 
MAX_THREADS = 100 

COMMON_PORTS_MAPPING = {
    20: "FTP (Data)", 21: "FTP (Control)", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 137: "NetBIOS",
    138: "NetBIOS Datagram", 139: "NetBIOS Session", 143: "IMAP", 161: "SNMP", 
    162: "SNMP Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB/MS DS", 500: "IKE (VPN)",
    3389: "RDP", 5900: "VNC", 8080: "HTTP Proxy/Alt"
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"ERROR: Could not determine local IP. Check network connection. ({e})")
        return None

def calculate_network_range_ips(ip_address):
    if ip_address:
        ip_network = ipaddress.ip_network(f'{ip_address}/24', strict=False)
        local_ip = ipaddress.IPv4Address(ip_address)
        host_ips = [str(ip) for ip in ip_network.hosts() if ip != local_ip]
        return host_ips, str(ip_network)
    return [], None

def authenticate_user():
    print("--- Security Authorization Required ---")
    print("WARNING: This tool performs an intensive security scan. Ensure you have explicit authorization for the target network.")
    print("Unauthorized scanning may carry legal issues. The author is not responsible for any damage caused by misuse.")
    password = input("Enter say 'yes' to proceed and accept the conditions: ").strip()
    
    if password == WIFI_PASSWORD_MOCK:
        print("\nAuthentication successful. Starting network scan.")
        return True
    else:
        print("\nAuthentication failed. Cannot proceed with the scan.")
        return False

def get_scan_configuration():
    global SCAN_PORTS_LIST
    print("\n--- Scan Configuration ---")
    print("Please select the type of port scan you want to perform:")
    print("1: Quick Scan (1-1024) - Fast, covers common services.")
    print("2: Comprehensive Scan (1-5000) - Balanced, covers many known service ports.")
    print("3: Full Scan (1-65535) - Very slow, intensive scan of all ports.")
    print("4: Custom Range")
    
    choice = input("Enter choice (1-4): ").strip()
    
    if choice == '1':
        SCAN_PORTS_LIST = list(range(1, 1025))
    elif choice == '2':
        SCAN_PORTS_LIST = list(range(1, 5001))
    elif choice == '3':
        SCAN_PORTS_LIST = list(range(1, 65536))
        print("WARNING: Full Scan (65535 ports) can take several hours depending on network size and speed.")
    elif choice == '4':
        while True:
            try:
                start_port = int(input("Enter starting port (e.g., 1): "))
                end_port = int(input("Enter ending port (e.g., 10000): "))
                if 1 <= start_port <= 65535 and start_port <= end_port <= 65535:
                    SCAN_PORTS_LIST = list(range(start_port, end_port + 1))
                    break
                else:
                    print("Invalid port range. Ports must be between 1 and 65535, and start must be less than or equal to end.")
            except ValueError:
                print("Invalid input. Please enter numbers only.")
    else:
        print("Invalid choice. Defaulting to Quick Scan (1-1024).")
        SCAN_PORTS_LIST = list(range(1, 1025))

    print(f"Configuration set: Scanning {len(SCAN_PORTS_LIST)} ports per active host.")


def check_liveness(ip):
    common_ports = [22, 80, 443, 445]
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) 
        try:
            sock.connect((ip, port))
            sock.close()
            return ip 
        except (socket.timeout, ConnectionRefusedError, OSError):
            sock.close()
            continue
    return None 

def discover_active_hosts(ip_list):
    print("\n[PHASE 1] Starting quick host discovery across the subnet...")
    
    start_time = time.time()
    active_hosts = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_liveness, ip): ip for ip in ip_list}
        
        for future in futures:
            result_ip = future.result()
            if result_ip:
                active_hosts.append(result_ip)

    end_time = time.time()
    print(f"Host discovery completed in {end_time - start_time:.2f} seconds.")
    print(f"Found {len(active_hosts)} active hosts to scan.")
    return active_hosts

def scan_port_details(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    
    try:
        start_connect_time = time.time()
        sock.connect((ip, port))
        connect_duration = time.time() - start_connect_time
        
        service_name = COMMON_PORTS_MAPPING.get(port, socket.getservbyport(port, 'tcp') if port < 65535 else 'Unknown')
        
        banner = ""
        try:
            if port in [21, 22, 23, 25, 80, 110, 143, 443]:
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n' if port == 80 else b'') 
            
            data = sock.recv(4096)
            banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0]
        except (socket.timeout, ConnectionResetError):
            pass

        banner_info = banner[:80] if banner else f"No banner (Service: {service_name})"
        
        return f"Open ({connect_duration:.2f}s) | Status: OPEN | Service: {service_name} | Banner: {banner_info}"
        
    except socket.timeout:
        return "Closed/Filtered (Timeout)"
    except ConnectionRefusedError:
        return "Closed (Refused)"
    except OSError as e:
        return f"Closed/Filtered (OS Error: {e})"
    except:
        return f"Closed/Filtered (General Error)"
    finally:
        sock.close()

def scan_host_full(host_ip):
    open_ports_results = {}
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_port = {executor.submit(scan_port_details, host_ip, port): port for port in SCAN_PORTS_LIST}
        
        for future in future_to_port:
            port = future_to_port[future]
            try:
                result = future.result()
                if "OPEN" in result:
                    open_ports_results[port] = result
            except Exception as exc:
                open_ports_results[port] = f"Error: {exc}"
    
    hostname = host_ip
    try:
        hostname = socket.gethostbyaddr(host_ip)[0]
    except socket.error:
        pass
        
    return hostname, open_ports_results

def main():
    if not authenticate_user():
        return
        
    get_scan_configuration()

    local_ip = get_local_ip()
    if not local_ip:
        return

    all_ips, target_network = calculate_network_range_ips(local_ip)
    if not all_ips:
        print("\nCould not determine network range.")
        return

    print(f"\nScanning local network segment: {target_network}")
    
    active_hosts = discover_active_hosts(all_ips)
    
    if not active_hosts:
        print("\nNo active devices found on the network (besides this scanner). Scan complete.")
        return
        
    total_hosts = len(active_hosts)
    ports_per_host = len(SCAN_PORTS_LIST)
    
    estimated_time_seconds = (ports_per_host * (TIMEOUT_SECONDS * 1.5) / MAX_THREADS) * total_hosts 
    estimated_minutes = int(estimated_time_seconds // 60)
    estimated_seconds = int(estimated_time_seconds % 60)
    
    print(f"\n[INFO] Estimated duration for deep port scan ({ports_per_host} ports/host): approximately {estimated_minutes} minutes and {estimated_seconds} seconds.")

    all_scan_results = []
    scan_start_time = time.time()
    
    # Track hosts successfully scanned to better estimate remaining time
    hosts_scanned_count = 0 

    for i, host_ip in enumerate(active_hosts):
        
        print(f"\n--- Scanning Host {i + 1}/{total_hosts}: {host_ip} ---")
        
        # Recalculate based on real progress
        time_elapsed = time.time() - scan_start_time
        
        # Calculate time remaining based on average time per host scanned so far
        if hosts_scanned_count > 0:
             average_time_per_host = time_elapsed / hosts_scanned_count
             time_remaining = (total_hosts - hosts_scanned_count) * average_time_per_host
        else:
             time_remaining = estimated_time_seconds
             
        remaining_minutes = int(time_remaining // 60)
        remaining_seconds = int(time_remaining % 60)
        
        print(f"[PROGRESS] Host {i + 1} of {total_hosts}. Elapsed: {time_elapsed:.0f}s. Estimated remaining: {remaining_minutes}m {remaining_seconds}s.")
        
        hostname, open_ports = scan_host_full(host_ip)
        hosts_scanned_count += 1
        
        # Check for web services and launch browser automatically
        if 80 in open_ports and "OPEN" in open_ports[80]:
            print(f"[ACTION] HTTP (Port 80) open. Attempting to open browser: http://{host_ip}")
            webbrowser.open_new_tab(f"http://{host_ip}")
        if 443 in open_ports and "OPEN" in open_ports[443]:
            print(f"[ACTION] HTTPS (Port 443) open. Attempting to open browser: https://{host_ip}")
            webbrowser.open_new_tab(f"https://{host_ip}")
            
        all_scan_results.append({
            'ip': host_ip,
            'hostname': hostname,
            'open_ports': open_ports
        })
    
    scan_end_time = time.time()
    
    
    print("\n=======================================================")
    print(f"COMPREHENSIVE SCAN COMPLETE! Total time: {scan_end_time - scan_start_time:.2f} seconds.")
    print("=======================================================")
    
    print("\n\n--- SECURITY SCAN REPORT ---")
    print(f"Scanner IP: {local_ip}")
    print(f"Network Range Scanned: {target_network}")
    print(f"Total Active Devices Found: {total_hosts}\n")
    
    for entry in all_scan_results:
        print(f"--------------------------------------------------")
        print(f"DEVICE IP: {entry['ip']}")
        print(f"DEVICE NAME (Inferred): {entry['hostname']}")
        
        if entry['open_ports']:
            print("OPEN VULNERABILITY PORTS / ACTIVE SERVICES:")
            for port, detail in entry['open_ports'].items():
                print(f"  [PORT {port}] {detail}")
        else:
            print(f"No open ports found in the range {SCAN_PORTS_LIST[0]}-{SCAN_PORTS_LIST[-1]}.")
            
    print("--------------------------------------------------")

if __name__ == "__main__":
    main()
