import sys
import logging
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from datetime import datetime
import psutil
import scapy.all as scapy

# If npcap is installed, do NOT force the L2socket to be L3socket.
# (Comment out the following lines if present.)
# if sys.platform == "win32":
#     from scapy.all import conf
#     conf.L2socket = conf.L3socket

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")
        self.setup_logging()

        # Create a Notebook with two tabs: one for packet capture and one for network devices.
        self.notebook = ttk.Notebook(master)
        self.capture_frame = ttk.Frame(self.notebook)
        self.devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.capture_frame, text="Packet Capture")
        self.notebook.add(self.devices_frame, text="Network Devices")
        self.notebook.pack(expand=True, fill="both")

        # Set up the individual tabs.
        self.setup_capture_tab()
        self.setup_devices_tab()

        # Initialize a thread-safe queue for packet messages and a stop event for the sniffer thread.
        self.packet_queue = queue.Queue()
        self.sniffing_thread = None
        self.sniffing_event = threading.Event()  # When set, the sniffer thread will stop.
        self.captured_packets = []  # For saving as PCAP.
        self.saved_messages = []    # For saving as text.

        # Begin updating the packet display periodically.
        self.update_packet_display()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            stream=sys.stdout,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def list_interfaces(self):
        """Return a list of available network interface names."""
        try:
            interfaces = psutil.net_if_addrs()
            interface_names = list(interfaces.keys())
            return interface_names
        except Exception as e:
            messagebox.showerror("Error", f"Unable to list interfaces: {e}")
            return []

    def setup_capture_tab(self):
        """Set up the GUI components for the Packet Capture tab."""
        # Interface selection
        label_interface = ttk.Label(self.capture_frame, text="Interface:")
        label_interface.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_combobox = ttk.Combobox(
            self.capture_frame, values=self.list_interfaces(), width=20
        )
        self.interface_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Optional filter input
        label_filter = ttk.Label(self.capture_frame, text="Filter (optional):")
        label_filter.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.filter_entry = ttk.Entry(self.capture_frame, width=20)
        self.filter_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Buttons for starting/stopping the sniffer and saving packets
        self.start_button = ttk.Button(
            self.capture_frame, text="Start Sniffing", command=self.start_sniffer
        )
        self.start_button.grid(row=2, column=0, padx=5, pady=10)
        self.stop_button = ttk.Button(
            self.capture_frame, text="Stop Sniffing", command=self.stop_sniffer
        )
        self.stop_button.grid(row=2, column=1, padx=5, pady=10)
        self.save_button = ttk.Button(
            self.capture_frame, text="Save Packets (Text)", command=self.save_packets
        )
        self.save_button.grid(row=3, column=0, padx=5, pady=10)
        self.save_pcap_button = ttk.Button(
            self.capture_frame, text="Save Packets (PCAP)", command=self.save_packets_pcap
        )
        self.save_pcap_button.grid(row=3, column=1, padx=5, pady=10)

        # Status label
        self.status_label = ttk.Label(
            self.capture_frame, text="Status: Stopped", foreground="red"
        )
        self.status_label.grid(row=4, column=0, columnspan=2, pady=5)

        # ScrolledText widget to display captured packets
        self.packet_display = scrolledtext.ScrolledText(
            self.capture_frame, width=80, height=20
        )
        self.packet_display.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

    def setup_devices_tab(self):
        """Set up the GUI components for the Network Devices tab."""
        # Allow user to specify an IP range (CIDR notation)
        label_ip_range = ttk.Label(self.devices_frame, text="IP Range (CIDR):")
        label_ip_range.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.ip_range_entry = ttk.Entry(self.devices_frame, width=20)
        self.ip_range_entry.insert(0, "192.168.1.0/24")
        self.ip_range_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Button to scan for network devices
        self.devices_button = ttk.Button(
            self.devices_frame, text="Scan Network Devices", command=self.display_network_devices
        )
        self.devices_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

        # ScrolledText widget to display discovered devices
        self.devices_text = scrolledtext.ScrolledText(
            self.devices_frame, width=80, height=20
        )
        self.devices_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def update_packet_display(self):
        """Periodically check the queue for new packet messages and update the text widget."""
        try:
            while not self.packet_queue.empty():
                message = self.packet_queue.get()
                self.packet_display.insert(tk.END, message)
                self.packet_display.see(tk.END)
        except Exception as e:
            logging.error(f"Error updating packet display: {e}")
        self.master.after(100, self.update_packet_display)

    def packet_callback(self, packet):
        """Process each captured packet, format the details, and add them to the queue."""
        try:
            if packet.haslayer(scapy.IP):
                source_ip = packet[scapy.IP].src
                destination_ip = packet[scapy.IP].dst
                protocol = packet[scapy.IP].proto
                protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, "Other")

                message = (
                    f"Time: {datetime.now()}\n"
                    f"Source IP: {source_ip}\n"
                    f"Destination IP: {destination_ip}\n"
                    f"Protocol: {protocol_name}\n"
                )

                if packet.haslayer(scapy.TCP):
                    message += (
                        f"TCP Source Port: {packet[scapy.TCP].sport}\n"
                        f"TCP Destination Port: {packet[scapy.TCP].dport}\n"
                    )
                elif packet.haslayer(scapy.UDP):
                    message += (
                        f"UDP Source Port: {packet[scapy.UDP].sport}\n"
                        f"UDP Destination Port: {packet[scapy.UDP].dport}\n"
                    )

                if packet.haslayer(scapy.ARP):
                    message += f"ARP Request: {packet[scapy.ARP].psrc} -> {packet[scapy.ARP].pdst}\n"

                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    message += f"Raw Payload: {payload}\n"

                message += "=" * 40 + "\n"

                # Add the formatted message to the thread-safe queue.
                self.packet_queue.put(message)
                # Save the actual packet and message for later saving.
                self.captured_packets.append(packet)
                self.saved_messages.append(message)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def sniff_packets(self, interface, filter_str):
        """Start sniffing on the specified interface using Scapy."""
        try:
            scapy.sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                filter=filter_str,
                stop_filter=lambda x: self.sniffing_event.is_set()
            )
        except Exception as e:
            logging.error(f"Error in sniffing: {e}")
            messagebox.showerror("Error", f"Failed to start sniffing: {e}")

    def start_sniffer(self):
        """Start the sniffer on a separate thread."""
        interface = self.interface_combobox.get()
        filter_str = self.filter_entry.get()
        if not interface:
            messagebox.showerror("Error", "Please specify a network interface!")
            return

        if self.sniffing_thread is not None and self.sniffing_thread.is_alive():
            messagebox.showwarning("Warning", "Sniffer is already running!")
            return

        # Clear the event to ensure sniffing begins.
        self.sniffing_event.clear()
        self.sniffing_thread = threading.Thread(
            target=self.sniff_packets, args=(interface, filter_str)
        )
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()
        self.status_label.config(text="Status: Sniffing started", foreground="green")
        logging.info("Sniffer started")

    def stop_sniffer(self):
        """Signal the sniffer thread to stop."""
        if self.sniffing_thread is None:
            messagebox.showwarning("Warning", "Sniffer is not running!")
            return
        self.sniffing_event.set()
        self.status_label.config(text="Status: Sniffing stopped", foreground="red")
        logging.info("Sniffer stopped")

    def save_packets(self):
        """Save the captured packet details as a text file."""
        if not self.saved_messages:
            messagebox.showwarning("Warning", "No packets to save!")
            return

        save_file = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")]
        )
        if not save_file:
            return

        try:
            with open(save_file, 'w') as f:
                for message in self.saved_messages:
                    f.write(message + "\n")
            messagebox.showinfo("Success", f"Packets saved to {save_file}")
            logging.info(f"Packets saved to {save_file}")
        except Exception as e:
            logging.error(f"Error saving packets: {e}")
            messagebox.showerror("Error", f"Failed to save packets: {e}")

    def save_packets_pcap(self):
        """Save the captured packets as a PCAP file."""
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save!")
            return

        save_file = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")]
        )
        if not save_file:
            return

        try:
            scapy.wrpcap(save_file, self.captured_packets)
            messagebox.showinfo("Success", f"Packets saved to {save_file}")
            logging.info(f"Packets saved to {save_file}")
        except Exception as e:
            logging.error(f"Error saving PCAP: {e}")
            messagebox.showerror("Error", f"Failed to save packets: {e}")

    def display_network_devices(self):
        """Scan the specified IP range for devices using ARP and display the results."""
        ip_range = self.ip_range_entry.get()
        if not ip_range:
            messagebox.showerror("Error", "Please specify an IP range!")
            return

        try:
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            self.devices_text.delete(1.0, tk.END)
            if not answered_list:
                self.devices_text.insert(tk.END, "No devices found on the network.\n")
                return

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                self.devices_text.insert(tk.END, f"IP: {ip}   MAC: {mac}\n")
        except Exception as e:
            logging.error(f"Error scanning network devices: {e}")
            messagebox.showerror("Error", f"Failed to display network devices: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
