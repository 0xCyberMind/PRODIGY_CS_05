import socket
import struct
import binascii
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import os
import sys
if os.name != 'nt':
    import fcntl  # Needed for promisc mode on Linux setups

# This is a network packet analyzer tool, meant purely for learning and ethical use.
# Always get permission before sniffing on any network.
# Needs admin/root privileges for raw sockets.
# It grabs IP packets and shows stuff like IPs, protocol, TTL, and some payload in hex.
# Works on Windows (mostly incoming) and Linux (incoming and outgoing, pick your interface).

class PacketAnalyzer:
    def __init__(self, window):
        self.window = window
        self.window.title("Packet Analyzer Tool - Educational")

        # Putting together the main layout
        layout_frame = ttk.Frame(window, padding=10)
        layout_frame.pack(fill=tk.BOTH, expand=True)

        # Filters and options
        options_frame = ttk.LabelFrame(layout_frame, text="Settings & Filters", padding=5)
        options_frame.pack(fill=tk.X, pady=5)

        ttk.Label(options_frame, text="IP or URL to Filter:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.filter_field = ttk.Entry(options_frame, width=30)
        self.filter_field.grid(row=0, column=1, padx=5, pady=5)

        if os.name != 'nt':
            ttk.Label(options_frame, text="Interface (like wlan0 or eth0):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
            self.iface_field = ttk.Entry(options_frame, width=30)
            self.iface_field.insert(0, "wlan0")  # Changed default to wlan0, common for WiFi
            self.iface_field.grid(row=1, column=1, padx=5, pady=5)

        # Control buttons
        controls = ttk.Frame(layout_frame)
        controls.pack(pady=10)

        self.begin_btn = ttk.Button(controls, text="Start Sniffing", command=self.begin_analysis)
        self.begin_btn.pack(side=tk.LEFT, padx=5)

        self.halt_btn = ttk.Button(controls, text="Stop Sniffing", command=self.halt_analysis, state=tk.DISABLED)
        self.halt_btn.pack(side=tk.LEFT, padx=5)

        self.wipe_btn = ttk.Button(controls, text="Wipe Log", command=self.wipe_log)
        self.wipe_btn.pack(side=tk.LEFT, padx=5)

        # Log area
        self.log_area = scrolledtext.ScrolledText(layout_frame, wrap=tk.WORD, width=100, height=25, font=("Courier", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=5)

        self.running = False
        self.sniff_thread = None
        self.sock = None
        self.target_ip = None
        self.my_host = socket.gethostbyname(socket.gethostname())

        # Quick startup notes
        self.log_area.insert(tk.END, "Note: For ethical use only on your own networks.\n")
        if os.name == 'nt':
            self.log_area.insert(tk.END, "Windows note: Might only catch incoming traffic. Try turning off firewall briefly if needed.\n")
        else:
            self.log_area.insert(tk.END, "Linux note: Grabs both ways. Make sure interface is right.\n")

    def begin_analysis(self):
        if not self.running:
            # Grab the filter
            filt = self.filter_field.get().strip()
            self.target_ip = None
            if filt:
                try:
                    self.target_ip = socket.gethostbyname(filt) if ':' not in filt else filt
                    self.log_area.insert(tk.END, f"Setting filter to: {self.target_ip}\n")
                except socket.gaierror:
                    messagebox.showerror("Filter Issue", "Couldn't resolve that to an IP.")
                    return

            self.running = True
            self.begin_btn.config(state=tk.DISABLED)
            self.halt_btn.config(state=tk.NORMAL)
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            self.log_area.insert(tk.END, "Kicking off the packet sniff...\n")

    def halt_analysis(self):
        if self.running:
            self.running = False
            self.begin_btn.config(state=tk.NORMAL)
            self.halt_btn.config(state=tk.DISABLED)
            self.log_area.insert(tk.END, "Halting the sniff.\n")
            self._close_sock()

    def wipe_log(self):
        self.log_area.delete(1.0, tk.END)

    def _init_sock(self):
        try:
            if os.name == 'nt':
                proto = socket.IPPROTO_IP
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                self.sock.bind((self.my_host, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Assuming Linux
                iface = self.iface_field.get().strip() or 'wlan0'
                proto = socket.ntohs(0x0800)  # IP packets
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, proto)
                self.sock.bind((iface, 0))
                # Flip on promisc mode
                ifr_pack = struct.pack("16sH", iface.encode(), 0)
                curr_flags = fcntl.ioctl(self.sock.fileno(), 0x890B, ifr_pack)[16:18]
                flag_val = struct.unpack("H", curr_flags)[0]
                flag_val |= 0x100  # Promisc flag
                fcntl.ioctl(self.sock.fileno(), 0x890C, struct.pack("16sH", iface.encode(), flag_val))
                self.log_area.insert(tk.END, f"Promisc mode on for {iface}.\n")
        except Exception as err:
            self.window.after(0, lambda: messagebox.showerror("Sock Setup Fail", f"Socket init failed: {err}. Need root?"))
            self.halt_analysis()
            return False
        return True

    def sniff_packets(self):
        if not self._init_sock():
            return

        eth_size = 14 if os.name != 'nt' else 0  # Eth header on Linux

        while self.running:
            try:
                data, _ = self.sock.recvfrom(65565)

                # Handle eth header if Linux
                if os.name != 'nt':
                    eth_hdr = data[:14]
                    eth_unpack = struct.unpack('!6s6sH', eth_hdr)
                    if socket.ntohs(eth_unpack[2]) != 0x0800:
                        continue
                    ip_hdr = data[14:34]  # 14 + 20
                else:
                    ip_hdr = data[:20]

                ip_unpack = struct.unpack('!BBHHHBBH4s4s', ip_hdr)

                ver_ihl = ip_unpack[0]
                ver = ver_ihl >> 4
                if ver != 4:  # Stick to IPv4
                    continue
                ihl_val = ver_ihl & 0xF
                ip_size = ihl_val * 4

                ttl_val = ip_unpack[5]
                prot_val = ip_unpack[6]
                from_ip = socket.inet_ntoa(ip_unpack[8])
                to_ip = socket.inet_ntoa(ip_unpack[9])

                # Check against filter
                if self.target_ip and self.target_ip not in (from_ip, to_ip):
                    continue

                prot_str = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(prot_val, f'Other ({prot_val})')

                pay_load = data[eth_size + ip_size:]
                hex_pay = binascii.hexlify(pay_load).decode('utf-8')[:200]  # Limit to 100 bytes shown

                entry = "\n--- Sniffed Packet ---\n"
                entry += f"From: {from_ip}\n"
                entry += f"To: {to_ip}\n"
                entry += f"Prot: {prot_str}\n"
                entry += f"TTL: {ttl_val}\n"
                entry += f"Payload Hex (partial): {hex_pay}...\n"
                entry += "-" * 50 + "\n"

                self.window.after(0, lambda txt=entry: self.log_area.insert(tk.END, txt))

            except Exception as sniff_err:
                self.window.after(0, lambda e=sniff_err: self.log_area.insert(tk.END, f"Sniff error: {e}\n"))

        self._close_sock()

    def _close_sock(self):
        if self.sock:
            try:
                if os.name == 'nt':
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                else:
                    iface = self.iface_field.get().strip() or 'wlan0'
                    ifr_pack = struct.pack("16sH", iface.encode(), 0)
                    curr_flags = fcntl.ioctl(self.sock.fileno(), 0x890B, ifr_pack)[16:18]
                    flag_val = struct.unpack("H", curr_flags)[0]
                    flag_val &= ~0x100  # Turn off promisc
                    fcntl.ioctl(self.sock.fileno(), 0x890C, struct.pack("16sH", iface.encode(), flag_val))
                    self.log_area.insert(tk.END, f"Promisc off on {iface}.\n")
            except Exception as close_err:
                self.log_area.insert(tk.END, f"Close error: {close_err}\n")
            self.sock.close()
            self.sock = None

if __name__ == "__main__":
    main_win = tk.Tk()
    app = PacketAnalyzer(main_win)
    main_win.mainloop()