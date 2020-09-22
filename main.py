## IMPORT PYTHON PACKAGES

## Import the default Python 3.0 libraries used in the script
import csv
import logging
import logging.handlers
from datetime import datetime

## Import requests Python package (https://requests.readthedocs.io/en/master/)
import requests


## CONFIGURATION VARIABLES

## Please contact ZeroFOX to obtain this URL
url='your_zf_threatfeed_csv_url'

## Your NetWitness IP Address
ip_address='127.0.0.1'

## Port associated with the IP Address above
port=514


## MAIN FUNCTIONS

## Function to format messages to be sent as CEF
def format_message(threat):
    message = 'id=' + threat[0] + ' indicator_type=' + threat[1] + ' value=' + threat[2] + ' network=' + threat[3] + ' classification_id=' + threat[4] + ' classification_name=' + threat[5] + ' campaign_id=' + threat[6] + ' campaign_name=' + threat[7] + ' campaign_id=' + threat[8] + ' privacy_level=' + threat[9] + ' zf_created_at=' + threat[10] + ' zf_updated_at=' + threat[11] + ' threat_level=' + threat[12] + ' expired=' + threat[13] + ' ttl=' + threat[14]

    syslog_message = "CEF:0|ZeroFOX|ZF ThreatFeed|1.0|Unknown|ZeroFOXThreatFeed|Info|" + message

    return syslog_message


## Create Syslog Logging Handler
my_logger = logging.getLogger('CEFLogger')
my_logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address = (ip_address, port))
my_logger.addHandler(handler)


## Download and write daily generated CSV file of Threat Indicators from ZeroFOX.
## Note that this file will be overwritten each day.
file = requests.get(url)
file_content = file.content
csv_file = open('./files/indicators.csv', 'wb+')
csv_file.write(file_content)
csv_file.close()


## Write daily indicators as Syslog CEF.
with open('./files/indicators.csv') as csvfile:
    readCSV = csv.reader(csvfile, delimiter=',')
    for threat in readCSV:
        syslog_message = format_message(threat)
        my_logger.info(syslog_message)


## Write to logs.txt with current date and time after job completes
now = datetime.now()
dt_string = now.strftime("%Y/%m/%d %H:%M:%S")
logs = open('./files/logs.txt', 'a')
logs.write(dt_string + ' - Threat Feed upload complete.\n')
