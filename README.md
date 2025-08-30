# PRODIGY_CS_05
A Python-based Packet Analyzer Tool for educational purposes to analyze network traffic in real-time. Capture packets, filter by IP/URL, and view details like protocol type, TTL, and payload in hex. Works on both Windows and Linux. Requires admin/root privileges for raw socket access.

# Packet Analyzer Tool

**Packet Analyzer Tool** is an educational Python application that allows users to capture and analyze network packets in real-time. It displays details like **IP addresses**, **protocols**, **TTL (Time to Live)**, and partial **payloads**. The tool is designed for learning network traffic analysis and can be used on both **Windows** and **Linux** systems.

## Features
- **Packet Sniffing**: Capture both incoming and outgoing network packets.
- **IP/URL Filter**: Filter traffic based on IP addresses or URLs.
- **Protocol Support**: Supports **ICMP**, **TCP**, **UDP** protocols.
- **User-Friendly GUI**: Built with **Tkinter** for easy navigation and interaction.
- **Cross-Platform**: Compatible with **Windows** and **Linux** (requires admin/root privileges).
- **Payload Preview**: Displays partial packet payload in hexadecimal format.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/packet-analyzer.git
  
2. **Install Dependencies (if required):** 

Linux: Ensure your system has the necessary libraries for raw sockets.

Windows: Ensure proper permissions for raw socket access.

3. **Run the Script:**
   ```bash
    python packet_analyzer.py
      ```
4. **Start Sniffing:**

Press Start Sniffing to begin capturing packets.

Set a filter (IP or URL) to capture specific traffic.

5. **Stop Sniffing:**
   Press Stop Sniffing to stop the packet capture process.
   
6.**Clear Logs:**

  Press Wipe Log to clear the captured packet log.

### Example of Captured Packet Log
  ```bash
    --- Sniffed Packet ---
    From: 192.168.1.5
    To: 192.168.1.1
    Protocol: TCP
    TTL: 64
    Payload (Hex): 4500002f1c4640004006b1e6c0a80101c0a8010200d0078fbe4e7ffb820000000000000000...
    --------------------------------------------------
  ```
### Requirements

Python 3.x

Linux: fcntl for promiscuous mode and network interfaces.

Windows: Admin privileges for raw socket access.

### ⚠️ Disclaimer

Always ensure you have explicit permission before sniffing network traffic. Unauthorized packet sniffing is illegal and unethical.

### Author: bhaskar uttam 






