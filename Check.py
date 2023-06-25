from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
import json
import csv
import re
import argparse



vt_api_ip_addresses = VirusTotalAPIIPAddresses('YOUR_VT_API_KEY')



#dealing with arguments

argParser = argparse.ArgumentParser()
argParser.add_argument("-s", "--source", action='store', dest='source', help="CSV source file containing the IP addresses you want to assess") #dealing with IP source file
argParser.add_argument("-d", "--destination", action='store', dest='destination',help="CSV destination file to store assessed IP addresses ")


args = argParser.parse_args()

if args.source is None: #check if an argument was passed as source
    print('Enter CSV source file')

elif args.destination is None:  #check if an argument was passed as destination
    print('Please also enter the name of the CSV destination file')

else:


    source_file = args.source
    destination_file = args.destination




    with open(source_file, 'r') as f: 

        reader = csv.reader(f)

        ip_list =  []

        for row in reader:

            ip_list.extend(row)
            


        reputation_results = []

        for ip in ip_list:

            try:
                result = vt_api_ip_addresses.get_report(ip) #Get VT data
                json_data = json.loads(result) #convert data in json
                reputation = json_data["data"]["attributes"]["last_analysis_stats"] #Get analysis result
                reputation_results.append((ip, reputation)) #append ip concerned and reputation 


            except VirusTotalAPIError as err:

                print(err, err.err_code) 
        
                

    with open(destination_file, 'w') as f:

        csv_writer = csv.writer(f)

        for ip, reputation in reputation_results:

            reputation_json = json.dumps(reputation) #dump reputation and concerned ip in a CSV

            cleaned_reputation = reputation_json.replace('"', '').replace('{', '').replace('}', '') #Delete { and } and " 

            csv_writer.writerow([ip, cleaned_reputation]) #write rows in the CSV

