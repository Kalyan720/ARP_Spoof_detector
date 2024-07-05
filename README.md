<b>ARP Spoof Detector<b>
This Python script is designed to detect ARP spoofing attacks on your network.

Overview
Upon execution, the script utilizes the Scapy library to capture and store the IP and MAC addresses of devices present in the network. This information is organized into a dataframe using pandas for efficient management and comparison.

Detection Mechanism
The script continuously monitors the network for new devices. When a new device is detected, it conducts a scan to retrieve its IP address and MAC address. Subsequently, it compares this information with the data stored in the dataframe.

Alerting
If a match is found between the IP address or MAC address of the new device and any entry in the stored data, the script raises an alert. This alert serves as a notification of a potential ARP spoofing attack, allowing prompt action to be taken.

Usage
To use the script effectively, ensure you have Python installed along with the required libraries:

Scapy
Pandas
Run the script in a suitable environment where it can monitor network traffic effectively.

Disclaimer
This script is provided as-is, without any guarantees or warranties. It is intended for educational purposes and to raise awareness about ARP spoofing attacks. Use it responsibly and with permission on networks you own or have explicit consent to monitor.
