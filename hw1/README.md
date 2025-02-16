1. How to complie and run:
    a. using pyinstaller: 
        pyinstaller -F pktsniffer.py
    b. run pktsniffer executable in dist folder

2. Command Line Usage Examples:
    pktsniffer -r 1-30-25-WiFi.pcap -net 162.159.130.0 -c 50
    pktsniffer -r 1-30-25-WiFi.pcap -port 51480 -udp
    pktsniffer -r 1-30-25-WiFi.pcap -tcp -c 25