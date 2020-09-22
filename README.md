# ZeroFOX Threat Feed Forwarder
The following script will be used to download a daily CSV file of ZeroFOX Threat Feed indicators, convert those indicators to CEF format, and forward those indicators to a syslog receiver (RSA NetWitness, Sumo Logic, etc.)

## Minimum requirements
Python 3

Please note that this script will work for Python 2.7; however, as Python 2.7 has reached the end of life and will no longer receive official support, we strongly recommend using Python 3.

## Configurations
Please ensure that **url*, **ip_address**, and **port** are all correctly defined to ensure that you are able to pull and forward data. If you need help with the **url**, please contact your ZeroFOX account manager.

## Setup
The only non-native Python module that you will need to install is the **requests** module, a lightweight module used for making HTTP requests. This can be done as follows:

````
pip3 install requests
````

For more documentation on the **requests** module, please visit the official developer documentation.

## Initial Scan
After creating the folder structure, copying the script above, and installing the requests library, please run the following command within the folder:

````
python3 main.py
````

After running the command, you should see the content of Threat Feed indicators in the indicators.csv file. The logs.txt file will also be updated to show the date of the recent scan

## Daily Ongoing Scans
A new CSV file will be made available each day with new ZeroFOX Threat Feed indicators. As such, the main.py script will need to be scheduled to run each day to forward these indicators to a syslog receiver. There are many ways to do this using either the Windows Task Scheduler, OSX Automator, or any other cron-based task scheduling system.

Once the daily ongoing scan is created, the ZeroFOX Indicators will be pulled daily, converted to CEF, and forwarded to NetWitness. Please note that the indicators.csv file will be overwritten each day and a new line will be created in the logs.txt file to show the last date of successful scanning and forwarding.
