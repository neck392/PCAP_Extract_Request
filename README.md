# PCAP_Extract_Request
Extract packets according to delay time when a **Time-Based SQL injection** attack technique occurs in a pcap format file (**Wireshark**).

## Input Values 
Check **SLEEP()** in packet info.
```python
# Input .pcap format file
pcap_file = 'input_file.pcap'

# Input delay time for successful Time-Based SQL injection
setTime = 3
```
