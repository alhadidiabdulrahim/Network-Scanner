import nmap

def display_menu():
    print("\nNetwork Scanner Tool Menu:")
    print("1. Port & Services Scan (Nmap)")
    print("2. Vulnerability Scan (Nmap NSE)")
    print("3. Exit")

def nmap_scan(target, arguments='-sV'):
    nm = nmap.PortScanner()
    print("Scanning with Nmap...")
    nm.scan(hosts=target, arguments=arguments)
    return nm

def print_results(nm):
    if nm.all_hosts():
        print(f"\n{'PORT':<10}{'SERVICE':<20}{'VERSION'}")
        print("-" * 40)
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port].get('version', '')
                    print(f"{port:<10} {service:<20} {version}")
    else:
        print("No open ports found.")

def nmap_vuln_scan(target):
    nm = nmap.PortScanner()
    print("Scanning for vulnerabilities with Nmap NSE...")
    nm.scan(hosts=target, arguments='--script vuln')
    return nm

def print_vuln_results(nm):
    if nm.all_hosts():
        print(f"\n{'HOST':<20}{'PORT':<10}{'SERVICE':<20}{'VULNERABILITY'}")
        print("-" * 70)
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if 'script' in nm[host][proto][port]:
                        vulnerabilities = nm[host][proto][port]['script']
                        for vuln in vulnerabilities:
                            print(f"{host:<20}{port:<10}{nm[host][proto][port]['name']:<20}{vuln}")
    else:
        print("No vulnerabilities found.")

def main():
    while True:
        display_menu()
        choice = input("Please select an option (1-3): ")
        
        if choice == '1':
            target = input("Enter the target IP address: ")
            nm = nmap_scan(target)
            print_results(nm)
        elif choice == '2':
            target = input("Enter the target IP address: ")
            nm = nmap_vuln_scan(target)
            print_vuln_results(nm)
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
