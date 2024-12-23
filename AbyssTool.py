import os
import time
import base64
import socket
import requests
from pystyle import Colors, Colorate
from pywifi import PyWiFi
import whois
import dns.resolver
import random
import string
import subprocess
from colorama import Fore, init

LICENSE_FILE = "license.key"
PREDEFINED_LICENSE = "sertf-ab456-@Cfra-gat34"

init(autoreset=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def animated_text(text, color=Colors.green_to_blue, delay=0.05):
    for char in text:
        print(Colorate.Horizontal(color, char, 1), end='', flush=True)
        time.sleep(delay)
    print()

def display_logo():
    logo = """
 ▄▄▄       ▄▄▄▄ ▓██   ██▓  ██████   ██████    ▄▄▄█████▓ ▒█████   ▒█████   ██▓
▒████▄    ▓█████▄▒██  ██▒▒██    ▒ ▒██    ▒    ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒
▒██  ▀█▄  ▒██▒ ▄██▒██ ██░░ ▓██▄   ░ ▓██▄      ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░
░██▄▄▄▄██ ▒██░█▀  ░ ▐██▓░  ▒   ██▒  ▒   ██▒   ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░
 ▓█   ▓██▒░▓█  ▀█▓░ ██▒▓░▒██████▒▒▒██████▒▒     ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
 ▒▒   ▓▒█░░▒▓███▀▒ ██▒▒▒ ▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░     ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
  ▒   ▒▒ ░▒░▒   ░▓██ ░▒░ ░ ░▒  ░ ░░ ░▒  ░ ░       ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
  ░   ▒    ░    ░▒ ▒ ░░  ░  ░  ░  ░  ░  ░       ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░
      ░  ░ ░     ░ ░           ░        ░                  ░ ░      ░ ░      ░  ░
                ░░ ░                                                             
"""
    print(Colorate.Horizontal(Colors.blue_to_purple, logo, 1))
    print(Colorate.Horizontal(Colors.green_to_blue, "[ W3B TOOL: MULTITOOL INFO SYSTEM ]", 1))

def validate_license():
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, "r") as file:
            license_key = file.read().strip()
        if license_key == PREDEFINED_LICENSE:
            return True
    return False

def register_license():
    clear()
    animated_text("[LICENSE VERIFICATION]", Colors.green_to_blue)
    while True:
        license_key = input("Enter your license key: ").strip()
        if license_key == PREDEFINED_LICENSE:
            with open(LICENSE_FILE, "w") as file:
                file.write(license_key)
            animated_text("License key saved successfully!", Colors.blue_to_green)
            return
        else:
            animated_text("Invalid license key. Please try again.", Colors.red_to_yellow)

def decrypt_password():
    clear()
    animated_text("[DECRYPT PASSWORD]", Colors.green_to_blue)
    encrypted = input("Enter the encrypted password (Base64): ").strip()
    try:
        decrypted = base64.b64decode(encrypted).decode('utf-8')
        animated_text(f"Decrypted Password: {decrypted}", Colors.blue_to_green)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def encrypt_password():
    clear()
    animated_text("[ENCRYPT PASSWORD]", Colors.green_to_blue)
    password = input("Enter the password to encrypt: ").strip()
    try:
        encrypted = base64.b64encode(password.encode('utf-8')).decode('utf-8')
        animated_text(f"Encrypted Password: {encrypted}", Colors.blue_to_green)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def check_wifi():
    clear()
    animated_text("[CHECK WIFI]", Colors.green_to_blue)
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    if results:
        for network in results:
            animated_text(f"SSID: {network.ssid}", Colors.blue_to_green)
    else:
        animated_text("No networks found.", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def check_hostname():
    clear()
    animated_text("[CHECK HOSTNAME]", Colors.green_to_blue)
    hostname = socket.gethostname()
    animated_text(f"Hostname: {hostname}", Colors.blue_to_green)
    input("Press Enter to return to the menu...")

def ip_generator():
    clear()
    animated_text("[IP GENERATOR]", Colors.green_to_blue)
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    animated_text(f"Generated IP: {ip}", Colors.blue_to_green)
    input("Press Enter to return to the menu...")

def ip_lookup():
    clear()
    animated_text("[IP LOOKUP]", Colors.green_to_blue)
    ip = input("Enter the IP address: ").strip()
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        for key, value in response.items():
            animated_text(f"{key.capitalize()}: {value}", Colors.blue_to_green)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def webhook_info():
    clear()
    animated_text("[WEBHOOK INFO]", Colors.green_to_blue)
    webhook_url = input("Enter the webhook URL: ").strip()
    try:
        response = requests.get(webhook_url).json()
        for key, value in response.items():
            animated_text(f"{key.capitalize()}: {value}", Colors.blue_to_green)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def ip_port_scanner():
    clear()
    animated_text("[IP PORT SCANNER]", Colors.green_to_blue)
    target = input("Enter the target IP address: ").strip()
    ports = [21, 22, 80, 443, 3389, 8080, 3306]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((target, port)) == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        animated_text(f"Open Ports: {', '.join(map(str, open_ports))}", Colors.blue_to_green)
    else:
        animated_text("No open ports found.", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def ip_pinger():
    clear()
    animated_text("[IP PINGER]", Colors.green_to_blue)
    target = input("Enter the target IP or hostname: ").strip()
    response = os.system(f"ping -c 1 {target}")
    if response == 0:
        animated_text(f"Ping to {target} successful.", Colors.blue_to_green)
    else:
        animated_text(f"Ping to {target} failed.", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def only_spam():
    clear()
    animated_text("[ONLYSPAM]", Colors.green_to_blue)
    webhook_url = input("Enter the Discord webhook URL: ").strip()
    message = input("Enter the message to send: ").strip()
    try:
        data = {
            "content": message
        }
        response = requests.post(webhook_url, json=data)
        if response.status_code == 204:
            animated_text("Spam sent successfully!", Colors.blue_to_green)
        else:
            animated_text(f"Failed to send spam. Status code: {response.status_code}", Colors.red_to_yellow)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def vulnerability_scanner():
    clear()
    animated_text("[VULNERABILITY SCANNER]", Colors.green_to_blue)
    animated_text("Performing vulnerability scan... (Placeholder)", Colors.green_to_blue)
    target = input("Enter the target IP or domain to scan: ").strip()
    animated_text(f"Scanning {target} for vulnerabilities (Placeholder)...", Colors.blue_to_green)
    time.sleep(3)
    vulnerabilities = ["Open SSH on port 22", "Open HTTP on port 80", "No SQL Injection found"]
    if vulnerabilities:
        for vuln in vulnerabilities:
            animated_text(f"Vulnerability found: {vuln}", Colors.red_to_yellow)
    else:
        animated_text("No vulnerabilities found.", Colors.blue_to_green)
    input("Press Enter to return to the menu...")

def osint_tools():
    clear()
    animated_text("[OSINT TOOLS]", Colors.green_to_blue)
    animated_text("Performing WHOIS Lookup...", Colors.green_to_blue)
    domain = input("Enter the domain name: ").strip()
    try:
        domain_info = whois.whois(domain)
        for key, value in domain_info.items():
            animated_text(f"{key.capitalize()}: {value}", Colors.blue_to_green)
    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)
    input("Press Enter to return to the menu...")

def website_info():
    clear()
    animated_text("[WEBSITE INFO SCANNER]", Colors.green_to_blue)
    target = input("Enter the website URL: ").strip()

    try:
        ip = socket.gethostbyname(target)
        animated_text(f"IP Address: {ip}", Colors.blue_to_green)

        animated_text("Resolving DNS...", Colors.green_to_blue)
        resolver = dns.resolver.Resolver()
        for record_type in ['A', 'MX', 'NS']:
            try:
                answers = resolver.resolve(target, record_type)
                for answer in answers:
                    animated_text(f"{record_type}: {answer}", Colors.blue_to_green)
            except Exception as e:
                animated_text(f"No {record_type} records found.", Colors.red_to_yellow)

        animated_text("Scanning open ports...", Colors.green_to_blue)
        ports = [21, 22, 80, 443, 3389, 8080, 3306]
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        if open_ports:
            animated_text(f"Open Ports: {', '.join(map(str, open_ports))}", Colors.blue_to_green)
        else:
            animated_text("No open ports found.", Colors.red_to_yellow)

        animated_text("Extracting links from website...", Colors.green_to_blue)
        try:
            response = requests.get(f"http://{target}")
            links = [line.split('"')[1] for line in response.text.split() if 'href="' in line]
            if links:
                for link in links[:10]:
                    animated_text(f"Link: {link}", Colors.blue_to_green)
            else:
                animated_text("No links found.", Colors.red_to_yellow)
        except Exception as e:
            animated_text(f"Error fetching website: {e}", Colors.red_to_yellow)

    except Exception as e:
        animated_text(f"Error: {e}", Colors.red_to_yellow)

    input("Press Enter to return to the menu...")

def id_to_token():
    clear()
    animated_text("[ID TO TOKEN]", Colors.green_to_blue)

    ascii_art = """
                    -------------------------------------------------------------------------------------
                    | ██╗██████╗     ████████╗ ██████╗     ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗ |
                    | ██║██╔══██╗    ╚══██╔══╝██╔═══██╗    ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║ |
                    | ██║██║  ██║       ██║   ██║   ██║       ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║ |
                    | ██║██║  ██║       ██║   ██║   ██║       ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║ |
                    | ██║██████╔╝       ██║   ╚██████╔╝       ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║ |
                    | ╚═╝╚═════╝        ╚═╝    ╚═════╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ |
                    -------------------------------------------------------------------------------------
                                                   Discord : usrrabyss
                                             
                                            
"""
    print(Fore.MAGENTA + ascii_art)

    print(Fore.YELLOW + " [ENTER] USER ID : ", end="")
    userid = input()

    encodedBytes = base64.b64encode(userid.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8").rstrip("=")

    print(Fore.GREEN + f'\n [LOGS] TOKEN FIRST PART : {encodedStr}')

    def generate_random_token_part():
        return ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=27))

    def generate_discord_token():
        part1 = generate_random_token_part()
        part2 = generate_random_token_part()
        part3 = generate_random_token_part()
        return f"{part1}.{part2}.{part3}"

    search_permission = input(Fore.YELLOW + "\n [INPUT] Do you want to search for matching tokens? (y/n): ").lower()

    if search_permission == 'y':
        found = False
        attempt = 0
        start_time = time.time()
        max_duration = 20 * 60

        while not found:
            token_to_test = f"{encodedStr}.{generate_random_token_part()}.{generate_random_token_part()}"
            print(Fore.RED + f"\n [INFO] Trying token: {token_to_test}")

            headers = {
                'Authorization': token_to_test
            }
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)

            if response.status_code == 200:
                print(Fore.GREEN + f"\n [INFO] MATCHING TOKEN FOUND: {token_to_test}")
                print(Fore.MAGENTA + ascii_art)
                found = True

            attempt += 1

            if time.time() - start_time > max_duration:
                print(Fore.RED + "\n [INFO] Time limit reached (20 minutes). Exiting the search.")
                break

            time.sleep(0)

        if not found:
            print(Fore.RED + "\n [INFO] No matching token found in the given time.")
    else:
        print(Fore.RED + "\n [LOGS] Search aborted.")

    input("Press Enter to return to the menu...")

def main_menu():
    clear()
    display_logo()
    menu = """
    ╔═════════════════════════════════════════════════════════════╗
    ║ [1] Decrypt Password                      [9] IP Pinger     ║
    ║ [2] Encrypt Password                     [10] OnlySpam      ║
    ║ [3] Check WiFi (Nearby Networks)         [11] Tools Info    ║
    ║ [4] Check Hostname                       [12] OSINT Tools   ║
    ║ [5] IP Generator                         [13] Vulnerability ║
    ║ [6] IP Lookup                            [14] Website Info  ║
    ║ [7] Webhook Info                         [15] ID to Token   ║
    ║ [8] IP Port Scanner                      [16] Exit          ║
    ╚═════════════════════════════════════════════════════════════╝
    """
    print(Colorate.Horizontal(Colors.yellow_to_red, menu, 1))
    choice = input("[>] Enter your choice: ")
    return choice

def main():
    if not validate_license():
        register_license()

    while True:
        choice = main_menu()
        if choice == '1':
            decrypt_password()
        elif choice == '2':
            encrypt_password()
        elif choice == '3':
            check_wifi()
        elif choice == '4':
            check_hostname()
        elif choice == '5':
            ip_generator()
        elif choice == '6':
            ip_lookup()
        elif choice == '7':
            webhook_info()
        elif choice == '8':
            ip_port_scanner()
        elif choice == '9':
            ip_pinger()
        elif choice == '10':
            only_spam()
        elif choice == '11':
            tools_info()
        elif choice == '12':
            osint_tools()
        elif choice == '13':
            vulnerability_scanner()
        elif choice == '14':
            website_info()
        elif choice == '15':
            id_to_token()
        elif choice == '16':
            animated_text("Exiting program...", Colors.red_to_yellow)
            break
        else:
            animated_text("Invalid choice. Please select a valid option.", Colors.red_to_yellow)

if __name__ == "__main__":
    main()
