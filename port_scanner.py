import socket
import time
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# --- SETTINGS ---
TIMEOUT = 0.5          # Timeout for port connection attempt (seconds)
BANNER_TIMEOUT = 1.0   # Timeout for grabbing the banner (seconds)
MAX_THREADS = 100      # Maximum number of concurrent threads

def print_banner(target_ip, start_port, end_port):
    print("-" * 70)
    print("PORT SCANNER")
    print("     [Port Resolution, Banner Grabbing & Reporting]")
    print("-" * 70)
    print(f"Target IP      : {target_ip}")
    print(f"Scan Range     : {start_port} - {end_port}")
    print(f"Start Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 70)

def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown Service"

def grab_banner(ip, port):
    """Attempts to connect to an open port and read the software version/banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(BANNER_TIMEOUT)
        s.connect((ip, port))
        
        # Some services (like HTTP) expect a request first.
        # So we send a standard HTTP GET request just in case.
        if port in [80, 443, 8080]:
            s.send(b"GET / HTTP/1.1\r\n\r\n")
            
        # Read the incoming response (Max 1024 bytes)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        # Clean up unnecessary whitespace and line breaks for better display
        banner = banner.replace('\r', '').replace('\n', ' | ')
        
        # Truncate the banner if it's too long
        return banner[:60] + "..." if len(banner) > 60 else banner
    except Exception:
        # Return empty if timeout occurs or connection drops
        return ""

def scan_port(ip, port, open_ports_list):
    """Checks if a single port is open; if so, gathers details."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            # If port is open, find the service and banner
            service = get_service_name(port)
            banner = grab_banner(ip, port)
            
            # Print to console for live tracking
            banner_info = f" [Banner: {banner}]" if banner else ""
            print(f"[+] Port {port:<5} : OPEN ({service.upper()}){banner_info}")
            
            # Add to list as a tuple for the final report
            open_ports_list.append((port, service, banner))
            
        s.close()
    except Exception:
        pass

def save_report(target_ip, start_port, end_port, open_ports, total_time):
    """Saves the scan results to a .txt file."""
    # Create filename based on target IP and current timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{target_ip.replace('.', '_')}_{timestamp}.txt"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("PORT SCAN REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f" Target IP      : {target_ip}\n")
            f.write(f" Scan Range     : {start_port} - {end_port}\n")
            f.write(f" Scan Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            if open_ports:
                f.write(f"{'PORT':<8} | {'SERVICE':<15} | {'VERSION / BANNER INFO'}\n")
                f.write("-" * 70 + "\n")
                for port, service, banner in open_ports:
                    display_banner = banner if banner else "No info retrieved"
                    f.write(f"{port:<8} | {service.upper():<15} | {display_banner}\n")
            else:
                f.write("No open ports found in the scanned range.\n")

            f.write("\n" + "=" * 70 + "\n")
            f.write(f" ⏳ Total Scan Time: {total_time:.2f} seconds\n")
            f.write("=" * 70 + "\n")

        print(f"\n[✔] Report successfully saved: {filename}")
    except Exception as e:
        print(f"\n[X] An error occurred while saving the report: {e}")

def main():
    print("Welcome to the Python Port Scanner!\n")
    
    target = input("Target IP or Domain (e.g., 192.168.1.1 or scanme.nmap.org): ").strip()
    
    if not target:
        print("[-] Error: Target address cannot be empty!")
        sys.exit()

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("\n[-] Error: Target could not be resolved (Invalid Domain or IP format).")
        sys.exit()

    try:
        start_port = input("Start Port (Default 1): ").strip()
        start_port = int(start_port) if start_port else 1
        
        end_port = input("End Port (Default 1024): ").strip()
        end_port = int(end_port) if end_port else 1024
    except ValueError:
        print("\n[-] Error: Please enter a valid port number (integer).")
        sys.exit()

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("\n[-] Error: Port range must be between 1 and 65535, and start <= end.")
        sys.exit()

    print_banner(target_ip, start_port, end_port)
    
    open_ports = []
    start_time = time.time()

    print("Scanning in progress, please wait...\n")

    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(scan_port, target_ip, port, open_ports)
                
    except KeyboardInterrupt:
        print("\n\n[!] Scan aborted by user! (CTRL+C)")
        sys.exit()

    end_time = time.time()
    total_time = end_time - start_time

    # Detailed Scan Report (Console Output)
    print("\n" + "=" * 70)
    print(" SCAN REPORT SUMMARY")
    print("=" * 70)
    
    if open_ports:
        print(f"Total of {len(open_ports)} open ports found:\n")
        open_ports.sort(key=lambda x: x[0]) # Sort by port number
        
        # Print as table
        print(f"{'PORT':<8} | {'SERVICE':<15} | {'VERSION / BANNER INFO'}")
        print("-" * 70)
        
        for port, service, banner in open_ports:
            display_banner = banner if banner else "No info retrieved"
            print(f"{port:<8} | {service.upper():<15} | {display_banner}")
    else:
        print("No open ports found in the scanned range.")
        
    print("-" * 70)
    print(f"⏳ Total scan time: {total_time:.2f} seconds")

    # Offer to save the report
    if open_ports:
        save_choice = input("\nWould you like to save these results to a .txt file? (Y/N): ").strip().lower()
        if save_choice == 'y':
            save_report(target_ip, start_port, end_port, open_ports, total_time)

if __name__ == "__main__":
    main()