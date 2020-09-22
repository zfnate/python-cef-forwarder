# ZeroFOX Threat Feed Forwarder
The following script will be used to download a daily CSV file of ZeroFOX Threat Feed indicators, convert those indicators to CEF format, and forward those indicators to a syslog receiver (RSA NetWitness, Sumo Logic, etc.)

## Minimum requirements
Python 3

Please note that this script will work for Python 2.7; however, as Python 2.7 has reached the end of life and will no longer receive official support, we strongly recommend using Python 3.
