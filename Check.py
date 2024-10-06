from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
import json
import csv
import argparse
import pandas as pd
import ipaddress

# ENTER YOUR API KEY
vt_api_ip_addresses = VirusTotalAPIIPAddresses('YOUR_KEY')

# ARGUMENTS
argParser = argparse.ArgumentParser()
argParser.add_argument("-s", "--source", action='store', dest='source', help="CSV source file containing the IP addresses you want to assess")  # fichier source
argParser.add_argument("-d", "--destination", action='store', dest='destination', help="CSV destination file to store assessed IP addresses")

args = argParser.parse_args()

# Check if arguments are there
if args.source is None:
    print('Please enter the CSV source file')
    exit(1)
elif args.destination is None:
    print('Please also enter the name of the CSV destination file')
    exit(1)

source_file = args.source
destination_file = args.destination

# CENSYS CIDR RANGE
excluded_ranges = [
    ipaddress.IPv4Network('66.132.148.0/24'),
    ipaddress.IPv4Network('66.132.153.0/24'),
    ipaddress.IPv4Network('66.132.159.0/24'),
    ipaddress.IPv4Network('162.142.125.0/24'),
    ipaddress.IPv4Network('167.94.138.0/24'),
    ipaddress.IPv4Network('167.248.133.0/24'),
    ipaddress.IPv4Network('206.168.32.0/24'),
    ipaddress.IPv4Network('206.168.33.0/24'),
    ipaddress.IPv4Network('206.168.34.0/24'),
    ipaddress.IPv4Network('206.168.35.0/24')
]

# read CSV with panda
try:
    df = pd.read_csv(source_file)
    ips = df['IP'].dropna().unique()  # check if double value
except FileNotFoundError:
    print(f"Source file {source_file} not found")
    exit(1)
except KeyError:
    print(f"Column 'IP' not found in {source_file}")
    exit(1)

if len(ips) == 0:
    print("No IP addresses found in the source file.")
    exit(1)

reputation_results = []

# check if IP address is in an excluded range
def is_ip_in_excluded_range(ip):
    ip_addr = ipaddress.IPv4Address(ip)
    return any(ip_addr in cidr for cidr in excluded_ranges)

# check every ip address
for ip in ips:
    # check if IP is in an excluded range
    if is_ip_in_excluded_range(ip):
        print(f"Skipping IP {ip} (in excluded range)")
        continue

    try:
        print(f"Analyzing IP: {ip}")
        result = vt_api_ip_addresses.get_report(ip)  
        json_data = json.loads(result) 

        
        if "data" in json_data and "attributes" in json_data["data"]:
            reputation = json_data["data"]["attributes"]["last_analysis_stats"]
            reputation_results.append((ip, reputation))
        else:
            print(f"No analysis data found for IP {ip}. Response: {json_data}")

    except VirusTotalAPIError as err:
        print(f"Error with IP {ip}: {err}, Code: {err.err_code}")
    except json.JSONDecodeError:
        print(f"Error decoding JSON for IP {ip}. Raw response: {result}")

# write results
with open(destination_file, 'w', newline='') as f:
    csv_writer = csv.writer(f)
    csv_writer.writerow(["IP Address", "Reputation"])  

    for ip, reputation in reputation_results:
        cleaned_reputation = json.dumps(reputation).replace('"', '').replace('{', '').replace('}', '')  
        csv_writer.writerow([ip, cleaned_reputation])  

print(f"Results written to {destination_file}")
