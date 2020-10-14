## Import the default Python 3.0 libraries used in the script
import csv
import logging
import logging.handlers
from datetime import datetime
from urllib.request import urlopen
from io import StringIO

## Set configuration variables
url='https://zf-tf-csv.s3.amazonaws.com/c804c5fb-0760-4193-9210-550e8a1765f9.csv'
ip_address='127.0.0.1'
port=514

## Get RSA NetWitness Event Type Based on indicator_type
def getType(indicator_type, indicator_value):
    type_switch = {
        'profile': 'url',
        'post': 'url',
        'page': 'url',
        'hashtag': 'obj_val',
        'non-social': 'url',
        'phoneNumber': 'phone',
        'email': 'email',
        'file_hash_md5': 'checksum',
        'file_hash_sha1': 'checksum',
        'file_hash_sha512': 'checksum',
        'ipv4_address': 'alias_ip',
        'btc_wallet': 'obj_val',
        'domain': 'url'
    }

    return ' ' + type_switch[indicator_type] + '=' + indicator_value

## Get Threat Indicator Threat Level and Convert to CEF Threat Level.
def getThreatLevel(threat_level):
    threat_switch = {
        'info': 'Info',
        'low': 'Notice',
        'medium': 'Warning',
        'high': 'Critical',
        'critical': 'Alert',
    }

    return threat_switch[threat_level] + '|'

## Function to format messages to be sent as CEF
def format_message(threat):
    threat_type_and_value = getType(threat[1], threat[2])

    message = 'ob_id=zf_' + threat[0] + ' obj_type=' + threat[1] + threat_type_and_value + ' netname=' + threat[3] + ' classification_id=' + threat[4] + ' alert=' + threat[5] + ' campaign_id=' + threat[6] + ' campaign_name=' + threat[7] + ' campaign_description=' + threat[8] + ' privacy_level=' + threat[9] + ' event_time=' + threat[10] + ' zf_updated_at=' + threat[11] + ' threat_level=' + threat[12] + ' expired=' + threat[13] + ' ttl=' + threat[14]

    syslog_message = 'CEF:0|ZeroFOX|ZF ThreatFeed|1.0|Unknown|ZeroFOXThreatFeed|' +  getThreatLevel(threat[12]) + message

    print (syslog_message + '\n')

    return syslog_message

## Create Syslog Logging Handler
my_logger = logging.getLogger('CEFLogger')
my_logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address = (ip_address, port))
my_logger.addHandler(handler)

## Download and write a daily generated CSV file of Threat Indicators from ZeroFOX.
file = urlopen(url).read().decode('utf-8','ignore')
file_content = StringIO(file)
readCSV = csv.reader(file_content)

for threat in readCSV:
    syslog_message = format_message(threat)
    my_logger.info(syslog_message)

## Write to logs.txt with current date and time after job completes
now = datetime.now()
dt_string = now.strftime("%Y/%m/%d %H:%M:%S")
logs = open('./files/logs.txt', 'a')
logs.write(dt_string + ' - Threat Feed upload complete.\n')
