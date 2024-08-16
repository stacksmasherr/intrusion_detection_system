import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import os
import sys

# Function to check if running as root
def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root. Please use 'sudo'.")
        sys.exit(1)

# Run the root check before proceeding
check_root()

# Initialize the main window
window = tk.Tk()
window.title("Network Intrusion Detection System (NIDS)")
window.geometry("1600x800")

# Global variables
capturing = False
packet_history = []  # List to store all packets for saving
alerts = []  # List to store detected alerts

# Functions to handle button actions
def start_capture():
    global capturing
    capturing = True
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

def stop_capture():
    global capturing
    capturing = False

def sniff_packets():
    sniff(prn=process_packet, stop_filter=lambda x: not capturing)

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet.sprintf("%IP.proto%")

        # Append packet to history for saving later
        packet_info = f"{ip_src} -> {ip_dst} [{protocol}]"
        packet_history.append(packet_info)

        # Display every packet in all_packets_listbox
        all_packets_listbox.insert(tk.END, packet_info + "\n")
        all_packets_listbox.yview(tk.END)

        # Filter and display TCP packets
        if TCP in packet:
            tcp_packets_listbox.insert(tk.END, packet_info + " [TCP]\n")
            tcp_packets_listbox.yview(tk.END)

            # Intrusion detection logic for TCP packets
            if packet[TCP].flags == 'S':  # SYN flag detection
                alert = f"Potential SYN scan from {ip_src} to {ip_dst}"
                alerts.append(alert)
                alerts_listbox.insert(tk.END, alert + "\n")
                alerts_listbox.yview(tk.END)

        # Filter and display UDP packets
        if UDP in packet:
            udp_packets_listbox.insert(tk.END, packet_info + " [UDP]\n")
            udp_packets_listbox.yview(tk.END)

            # Intrusion detection logic for UDP packets
            if len(packet) > 1000:  # Example rule for large UDP packets
                alert = f"Large UDP packet detected from {ip_src} to {ip_dst}"
                alerts.append(alert)
                alerts_listbox.insert(tk.END, alert + "\n")
                alerts_listbox.yview(tk.END)

        # Filter and display ICMP packets
        if ICMP in packet:
            icmp_packets_listbox.insert(tk.END, packet_info + " [ICMP]\n")
            icmp_packets_listbox.yview(tk.END)

            # Intrusion detection logic for ICMP packets
            if packet[ICMP].type == 8:  # ICMP Echo Request (ping) detection
                alert = f"ICMP Echo Request from {ip_src} to {ip_dst}"
                alerts.append(alert)
                alerts_listbox.insert(tk.END, alert + "\n")
                alerts_listbox.yview(tk.END)

def save_alert():
    # Save the entire packet history to a text file
    with open("packet_history.txt", "w") as f:
        for packet in packet_history:
            f.write(packet + "\n")
    print("Packet history saved to packet_history.txt")

    # Save the detected alerts to a text file
    with open("alerts.txt", "w") as f:
        for alert in alerts:
            f.write(alert + "\n")
    print("Alerts saved to alerts.txt")

# Define layout elements
start_button = ttk.Button(window, text='STARTCAP', command=start_capture)
stop_button = ttk.Button(window, text='STOPCAP', command=stop_capture)
save_alert_button = ttk.Button(window, text='SAVE PACKET HISTORY & ALERTS', command=save_alert)
refresh_rules_button = ttk.Button(window, text='REFRESH RULES', command=lambda: print("Rules refreshed (Placeholder)"))

# Define labels
all_packets_label = ttk.Label(window, text="ALL PACKETS", font=('Arial Bold', 14))
tcp_packets_label = ttk.Label(window, text="TCP PACKETS", font=('Arial Bold', 14))
udp_packets_label = ttk.Label(window, text="UDP PACKETS", font=('Arial Bold', 14))
icmp_packets_label = ttk.Label(window, text="ICMP PACKETS", font=('Arial Bold', 14))
alerts_label = ttk.Label(window, text="ALERTS", font=('Arial Bold', 14))

# Define listboxes
all_packets_listbox = tk.Listbox(window, height=20, width=80)
tcp_packets_listbox = tk.Listbox(window, height=20, width=80)
udp_packets_listbox = tk.Listbox(window, height=20, width=80)
icmp_packets_listbox = tk.Listbox(window, height=20, width=80)
alerts_listbox = tk.Listbox(window, height=20, width=80)

# Positioning the elements in the grid
start_button.grid(row=0, column=0, padx=5, pady=5)
stop_button.grid(row=0, column=1, padx=5, pady=5)
save_alert_button.grid(row=0, column=2, padx=5, pady=5)
refresh_rules_button.grid(row=0, column=3, padx=5, pady=5)

all_packets_label.grid(row=1, column=0, padx=5, pady=5, sticky='w')
tcp_packets_label.grid(row=1, column=1, padx=5, pady=5, sticky='w')
udp_packets_label.grid(row=1, column=2, padx=5, pady=5, sticky='w')
icmp_packets_label.grid(row=1, column=3, padx=5, pady=5, sticky='w')
alerts_label.grid(row=1, column=4, padx=5, pady=5, sticky='w')

all_packets_listbox.grid(row=2, column=0, padx=5, pady=5)
tcp_packets_listbox.grid(row=2, column=1, padx=5, pady=5)
udp_packets_listbox.grid(row=2, column=2, padx=5, pady=5)
icmp_packets_listbox.grid(row=2, column=3, padx=5, pady=5)
alerts_listbox.grid(row=2, column=4, padx=5, pady=5)

# Start the tkinter main loop
window.mainloop()
