import sys
import threading
import csv
import json
import dpkt
import socket
import requests
from IP2Location import IP2Location
import webbrowser
from datetime import datetime



from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QAction, QHBoxLayout, QWidget, QPushButton, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QFileDialog, QMessageBox, QTextEdit, QFrame, QSpacerItem,
    QVBoxLayout, QSizePolicy, QLabel, QGroupBox, QDialog, QLineEdit, QListWidget, QGridLayout # Add QListWidget
)
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QColor, QBrush
from PyQt5.QtCore import Qt
from scapy.all import *
from PyQt5.QtGui import QImage, QPixmap, QPalette, QBrush

class WelcomeWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Welcome To GeoSniff-X\n A Network Capture Tool")
        self.setGeometry(200, 200, 400, 300)

        layout = QVBoxLayout()

        # Styled welcome message
        welcome_message = QLabel()
        welcome_message.setText("<html><head/><body><p><span style=' font-size:12pt; font-weight:600; color:#0070c0;'>Welcome to GeoSniff-X</span></p></body></html>")
        welcome_message.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_message)

        label = QLabel("Select a network interface to start capturing:")
        layout.addWidget(label)

        self.interface_list = QListWidget()
        layout.addWidget(self.interface_list)

        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_interfaces)
        layout.addWidget(refresh_button)

        select_button = QPushButton("Select Interface")
        select_button.clicked.connect(self.select_interface)
        layout.addWidget(select_button)

        self.setLayout(layout)

        self.refresh_interfaces()

 # Apply the same background color as NetworkCaptureApp
        self.setStyleSheet("""
            QDialog {
                background-color:#1A2E4B;
                color: #FFF;
            }
            QListWidget {
                background-color: #2C3E50 ;
                color: #FFF;
                alternate-background-color: #555;
                selection-background-color: #1A2E4B;
                selection-color: #FFF;
                border: 1px solid #666;
            }
            QPushButton {
                background-color: #1B2631;
                color: #FFF;
                border: 1px solid #1B4F72;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #005D7A;
                border: 1px solid #005D7A;
            }
            QPushButton:pressed {
                background-color: #004A5F;
                border: 1px solid #004A5F;
            }
            """)


    def refresh_interfaces(self):
        # Clear existing items
        self.interface_list.clear()

        # Get the list of available interfaces
        interfaces = get_if_list()
        for interface in interfaces:
            self.interface_list.addItem(interface)

    def select_interface(self):
        selected_item = self.interface_list.currentItem()
        if selected_item:
            interface_name = selected_item.text()
            # Close the welcome window and start the main application window with the selected interface
            print(f"Selected Interface: {interface_name}")
            self.close()
            self.main_window = NetworkCaptureApp(interface_name=interface_name)
            self.main_window.show()

class NetworkCaptureApp(QMainWindow):
    def __init__(self, interface_name):
        super().__init__()
        self.interface_name = interface_name
        self.capture_thread = None
        self.captured_packets = []
        self.filtered_packets = []  # List to store filtered packets
        self.stop_flag = False  # Flag to signal the capture thread to stop
        self.paused = False  # Flag to indicate whether capture is paused

         # Initialize frame_number_counter
        self.frame_number_counter = 0

        self.setWindowTitle("Network Capture Tool")
        self.setGeometry(100, 100, 900, 600)
 # Set the font to Spotify Circular
        font = QFont("Spotify Circular", 10)  # Change the size (10) as needed

        # Apply the font to the main window
        self.setFont(font)

 # Set the dark theme style sheet
        self.setStyleSheet("""
            QMainWindow {
                background-color:#1A2E4B;
                color: #FFF;
            }
            QTreeWidget {
                background-color: #2C3E50 ;
                color: #FFF;
                alternate-background-color: #555;
                selection-background-color: #B60505;
                selection-color: #FFF;
                border: 1px solid #666;
            }
            QTreeWidget::item:hover {
                background-color: #1A2E4B;
            }
            QMenuBar {
                background-color: #17202A;
                color: #FFF;
            }
            QMenuBar::item {
                background-color: #1A2E4B;
                color:  #FFF;
            }
            QMenuBar::item:selected {
                background-color: #007ACC;
                color: #FFF;
            }
            QPushButton {
                background-color: #1B2631;
                color: #FFF;
                border: 1px solid #1B4F72;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #005D7A;
                border: 1px solid #005D7A;
            }
            QPushButton:pressed {
                background-color: #004A5F;
                border: 1px solid #004A5F;
            }
            QLineEdit {
                background-color: #2C3D55;
                color: #FFF;
                border: 1px solid #666;
            }
            """)

        # Main Widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Define the menu actions as attributes
        self.start_capture_action = None
        self.stop_capture_action = None
        self.pause_capture_action = None
        self.resume_capture_action = None
        self.capture_stats_action = None


        # Menu Bar
        menu_bar = self.menuBar()

# Set font for the menu bar
        menu_bar.setFont(font)

        # File menu
        file_menu = menu_bar.addMenu("&File")

        new_action = QAction("&New", self)
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)

        open_action = QAction("&Open", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        save_action = QAction("&Save", self)
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)

        save_as_action = QAction("Save &As", self)
        save_as_action.triggered.connect(self.save_as_file)
        file_menu.addAction(save_as_action)

        file_menu.addSeparator()

        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)


        # Edit menu
        edit_menu = menu_bar.addMenu("&Edit")

        # Clear All Packets Action
        clear_packets_action = QAction("&Clear All Packets", self)
        clear_packets_action.triggered.connect(self.clear_all_packets)
        edit_menu.addAction(clear_packets_action)

        # Mark/Unmark Packet Action
        mark_unmark_packet_action = QAction("&Mark/Unmark Packet", self)
        mark_unmark_packet_action.triggered.connect(self.mark_unmark_packet)
        edit_menu.addAction(mark_unmark_packet_action)


        # Copy Packet Details
        copy_details_action = QAction("&Copy Packet Details", self)
        copy_details_action.triggered.connect(self.copy_packet_details)
        edit_menu.addAction(copy_details_action)


        # Delete Packet
        delete_packet_action = QAction("&Delete Packet", self)
        delete_packet_action.triggered.connect(self.delete_packet)
        edit_menu.addAction(delete_packet_action)

        # Capture menu
        capture_menu = menu_bar.addMenu("&Capture")

        # Start Capture Action
        start_capture_action = QAction("&Start Capture", self)
        start_capture_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_capture_action)

        # Stop Capture Action
        stop_capture_action = QAction("&Stop Capture", self)
        stop_capture_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_capture_action)

        # Pause Capture Action
        self.pause_capture_action = QAction("&Pause Capture", self)
        self.pause_capture_action.triggered.connect(self.pause_capture)
        capture_menu.addAction(self.pause_capture_action)

        # Resume Capture Action
        self.resume_capture_action = QAction("&Resume Capture", self)
        self.resume_capture_action.triggered.connect(self.resume_capture)
        capture_menu.addAction(self.resume_capture_action)

        # Capturing Statistics Action
        self.capture_stats_action = QAction("&Capturing Statistics", self)
        self.capture_stats_action.triggered.connect(self.show_capture_statistics)
        capture_menu.addAction(self.capture_stats_action)

        # Initial state: Start Capture enabled, Stop Capture disabled
        if self.start_capture_action is not None:
            self.start_capture_action.setEnabled(True)
        if self.stop_capture_action is not None:
            self.stop_capture_action.setEnabled(False)
        if self.pause_capture_action is not None:
            self.pause_capture_action.setEnabled(True)
        if self.resume_capture_action is not None:
            self.resume_capture_action.setEnabled(True)

        # Add a submenu for "Unauthorized Packet"
        unauthorized_packet_menu = capture_menu.addMenu("Unauthorized Packet")

        # Add actions or functionalities related to unauthorized packets under this submenu

        unauthorized_packet_action = QAction("Capture Unauthorized Packets", self)
        unauthorized_packet_action.triggered.connect(self.capture_unauthorized_packets)
        unauthorized_packet_menu.addAction(unauthorized_packet_action)

        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        # Add Help Action
        help_action = QAction("&Help", self)
        help_action.triggered.connect(self.open_help_link)
        help_menu.addAction(help_action)

        # Toolbar
        toolbar = QFrame()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setAlignment(Qt.AlignLeft)
        toolbar.setLayout(toolbar_layout)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        toolbar_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        toolbar_layout.addWidget(self.stop_button)

        # Add Refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_packet_list)
        toolbar_layout.addWidget(self.refresh_button)


        spacer_item = QSpacerItem(10, 10, QSizePolicy.Expanding, QSizePolicy.Minimum)
        toolbar_layout.addItem(spacer_item)

        self.analyze_button = QPushButton("Packet Analyzer")
        self.analyze_button.clicked.connect(self.analyze_packet)
        self.analyze_button.setEnabled(False)
        toolbar_layout.addWidget(self.analyze_button)

        self.export_button = QPushButton("Export Packets")
        self.export_button.clicked.connect(self.export_packets)
        self.export_button.setEnabled(False)
        toolbar_layout.addWidget(self.export_button)

        self.selectFileButton = QPushButton('Select PCAP File', self)
        self.selectFileButton.clicked.connect(self.selectFile)
        toolbar_layout.addWidget(self.selectFileButton)

        self.open_maps_button = QPushButton("Open Google Maps")
        self.open_maps_button.clicked.connect(self.open_google_maps)
        toolbar_layout.addWidget(self.open_maps_button)

        main_layout.addWidget(toolbar)

        # Filter section
        filter_label = QLabel("Display Filter Expression:")
        main_layout.addWidget(filter_label)

        self.display_filter_input = QLineEdit()
        main_layout.addWidget(self.display_filter_input)

        apply_display_filter_button = QPushButton("Apply Display Filter")
        apply_display_filter_button.clicked.connect(self.apply_display_filter)
        main_layout.addWidget(apply_display_filter_button)

        # Packet List
        self.packet_list = QTreeWidget()
        self.packet_list.setColumnCount(11)  # Update the number of columns to accommodate the new fields
        self.packet_list.setHeaderLabels(
            ["Frame Number", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol",
             "Length", "Source MAC", "Destination MAC", "Info"])  # Update header labels to match the new fields
        self.packet_list.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_list.itemSelectionChanged.connect(self.enable_analyze_button)
        # Set font for the packet list
        self.packet_list.setFont(font)

        main_layout.addWidget(self.packet_list)

        self.capture_thread = None
        self.captured_packets = []



    def export_packets(self):
        if not self.captured_packets:
            QMessageBox.warning(self, "Export Packets", "No packets captured to export.")
            return

        options = "PCAP files (.pcap);;CSV files (.csv);;JSON files (.json);;TCPDump files (.pcap)"
        filename, _ = QFileDialog.getSaveFileName(self, "Export Packets", "", options)
        if filename:
            if filename.endswith('.pcap'):
                wrpcap(filename, self.captured_packets)
                QMessageBox.information(self, "Export Packets", f"Packets exported to {filename}.")
            elif filename.endswith('.csv'):
                with open(filename, 'w') as csvfile:
                    csv_writer = csv.writer(csvfile)
                    for pkt in self.captured_packets:
                        # Write packet data to CSV file
                        csv_writer.writerow([str(pkt.time), pkt[IP].src, pkt[IP].dst, pkt.payload.name, str(len(pkt)), pkt.summary()])
                QMessageBox.information(self, "Export Packets", f"Packets exported to {filename}.")
            elif filename.endswith('.json'):
                packets_data = []
                for pkt in self.captured_packets:
                    packet_info = {
                        "Time": str(pkt.time),
                        "Source IP": pkt[IP].src,
                        "Destination IP": pkt[IP].dst,
                        "Protocol": pkt.payload.name,
                        "Length": str(len(pkt)),
                        "Info": pkt.summary()
                    }
                    packets_data.append(packet_info)
                with open(filename, 'w') as jsonfile:
                    json.dump(packets_data, jsonfile, indent=4)
                QMessageBox.information(self, "Export Packets", f"Packets exported to {filename}.")
            elif filename.endswith('tcpdump.pcap'):
                # Convert to tcpdump format
                self.export_to_tcpdump(filename)
                QMessageBox.information(self, "Export Packets", f"Packets exported to {filename}.")
            else:
                QMessageBox.warning(self, "Export Packets", "Unsupported file format.")

    def delete_packet(self):
        selected_items = self.packet_list.selectedItems()
        if selected_items:
            # Ask for confirmation before deleting
            reply = QMessageBox.question(self, 'Confirmation',
                                         'Are you sure you want to delete the selected packet(s)?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                for item in selected_items:
                    index = self.packet_list.indexOfTopLevelItem(item)
                    if index != -1:
                        self.packet_list.takeTopLevelItem(index)
                        del self.captured_packets[index]

    def open_help_link(self):
        url = "https://arjun364.github.io/GEOSNIFFX-HELP-PAGE/"
        webbrowser.open_new_tab(url)
    def clear_all_packets(self):
        # Clears the packet display
        self.packet_list.clear()
        # Assuming self.captured_packets is your internal storage
        self.captured_packets.clear()

    def get_firehol_ip_lists(self):
        # Download FireHOL IP Lists and parse them to extract IP addresses
        firehol_url = "https://iplists.firehol.org/files/firehol_level1.netset"
        try:
            response = requests.get(firehol_url)
            response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
            ip_list = response.text.split("\n")
            # Remove empty lines and comments
            ip_list = [ip.strip() for ip in ip_list if ip.strip() and not ip.strip().startswith("#")]
            return ip_list
        except requests.RequestException as e:
            # Handle request exceptions (e.g., network errors)
            print(f"Error downloading FireHOL IP Lists: {e}")
            return []

    def capture_unauthorized_packets(self):
        unauthorized_packets = []
        unauthorized_ips = self.get_firehol_ip_lists()  # Get FireHOL IP Lists

        if not unauthorized_ips:
            # Handle case where IP list retrieval fails
            QMessageBox.warning(self, "Unauthorized Packets", "Failed to retrieve unauthorized IP list.")
            return

        # Check each captured packet for unauthorized IPs
        for pkt in self.captured_packets:
            if IP in pkt:
                if pkt[IP].src in unauthorized_ips or pkt[IP].dst in unauthorized_ips:
                    unauthorized_packets.append(pkt)

        if unauthorized_packets:
            # Display unauthorized packets
            self.display_unauthorized_packets(unauthorized_packets)
        else:
            # Show message if no unauthorized packets found
            QMessageBox.information(self, "Unauthorized Packets", "No unauthorized packets found.")


    def pause_capture(self):
        if not self.paused:
            self.paused = True
            self.stop_capture()
            QMessageBox.information(self, "Capture Paused", "Packet capture has been paused.")


    def resume_capture(self):
        if self.paused:
            self.paused = False
            self.start_capture()
            QMessageBox.information(self, "Capture Resumed", "Packet capture has been resumed.")

    def show_capture_statistics(self):
        total_packets = len(self.captured_packets)
        capture_duration = self.calculate_capture_duration()
        average_packets_per_second = total_packets / capture_duration if capture_duration > 0 else 0

        # Constructing the message
        message = f"Total packets captured: {total_packets}\n"
        message += f"Capture duration: {capture_duration} seconds\n"
        message += f"Average packets per second: {average_packets_per_second:.2f}"

        QMessageBox.information(self, "Capturing Statistics", message)

    def calculate_capture_duration(self):
        # Calculate the duration of the capture in seconds
        if self.captured_packets:
            start_time = self.captured_packets[0].time  # Assume these are already float timestamps
            end_time = self.captured_packets[-1].time
            duration = end_time - start_time  # This will already be a float representing seconds
            return duration  # Directly return the duration in seconds
        else:
            return 0

    def copy_packet_details(self):
        selected_items = self.packet_list.selectedItems()
        if selected_items:
            # Get the text of each selected item
            packet_details = [item.text(column) for item in selected_items for column in
                              range(self.packet_list.columnCount())]
            # Join the details into a single string
            packet_details_text = '\n'.join(packet_details)
            # Copy the packet details to the clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(packet_details_text)

    def mark_unmark_packet(self):
        selected_items = self.packet_list.selectedItems()
        if not selected_items:
            return  # No selection made

        for item in selected_items:
            column_count = self.packet_list.columnCount()  # Get the number of columns
            is_marked = item.background(0).color() == QColor('yellow')  # Check if already marked

            for col in range(column_count):  # Apply changes to all columns
                if is_marked:
                    # If already marked, unmark it by setting the background to default
                    item.setBackground(col, QBrush(QColor('transparent')))
                else:
                    # If not marked, mark it with yellow
                    item.setBackground(col, QBrush(QColor('yellow')))

    def export_to_tcpdump(self, filename):
        # Write captured packets to a file in pcap format
        wrpcap(filename, self.captured_packets)

    def start_capture(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Reset stop_flag
        self.stop_flag = False
        # Start capturing packets using the selected interface
        self.capture_thread = threading.Thread(target=self.packet_capture_thread)
        self.capture_thread.start()

    def stop_capture(self):
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        # Set the stop flag to signal the capture thread to stop
        self.stop_flag = True

    def refresh_packet_list(self):
        # Clear the current packet list
        self.packet_list.clear()

        # Reset the frame number counter
        self.frame_number_counter = 0

        # Display the captured packets again
        for pkt in self.captured_packets:
            self.display_captured_packets(pkt)

    def packet_capture_thread(self):
        # Implement the packet capturing logic here
        # For demonstration purposes, let's print captured packets
        sniff(prn=self.packet_callback, iface=self.interface_name)

    def packet_callback(self, pkt):
        # Process the captured packet and display it in the packet list
        try:
            if not self.stop_flag:
                self.captured_packets.append(pkt)
                self.display_captured_packets(pkt)
        except Exception as e:
            print("An error occurred while processing the packet:", e)

    def display_captured_packets(self, pkt):
        try:
            self.frame_number_counter += 1

            frame_number = self.frame_number_counter
            source_ip = ""
            dest_ip = ""
            source_port = ""
            dest_port = ""
            protocol = ""
            length = len(pkt)
            source_mac = ""
            dest_mac = ""
            info = pkt.summary()

            if IP in pkt:
                source_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
                protocol = self.get_protocol_name(pkt.proto)

            if TCP in pkt:
                source_port = pkt[TCP].sport
                dest_port = pkt[TCP].dport
            elif UDP in pkt:
                source_port = pkt[UDP].sport
                dest_port = pkt[UDP].dport

            if Ether in pkt:
                source_mac = pkt[Ether].src
                dest_mac = pkt[Ether].dst

            item = QTreeWidgetItem([
                str(frame_number), str(pkt.time), source_ip, dest_ip,
                str(source_port), str(dest_port), protocol, str(length), source_mac, dest_mac, info
            ])

            # Color code the packet based on its protocol
            color = QColor()
            if protocol == 'TCP':
                color.setRgb(52, 73, 94)  # Yellow with reduced opacity
            elif protocol == 'UDP':
                color.setRgb(52, 152, 219)  # Green with reduced opacity
            elif protocol == 'ICMP':
                color.setRgb(130, 224, 170)  # Blue with reduced opacity
            elif protocol == 'ARP':
                color.setRgb(251, 2, 255)  # Blue with reduced opacity
            else:
                color.setRgb(251, 2, 255)  # White for other protocols

            for i in range(item.columnCount()):
                item.setBackground(i, QBrush(color))

            self.packet_list.addTopLevelItem(item)
        except Exception as e:
            print("An error occurred while displaying captured packet:", e)

    @staticmethod
    def get_protocol_name(proto_num):
        if proto_num == 6:
            return 'TCP'
        elif proto_num == 17:
            return 'UDP'
        elif proto_num == 1:
            return 'ICMP'
        elif proto_num == 20 or proto_num == 21:
            return 'FTP'
        elif proto_num == 25:
            return 'SMTP'
        elif proto_num == 110:
            return 'POP3'
        elif proto_num == 143:
            return 'IMAP'
        elif proto_num == 161:
            return 'SNMP'
        elif proto_num == 22:
            return 'SSH'
        elif proto_num == 23:
            return 'Telnet'
        elif proto_num == 5060 or proto_num == 5061:
            return 'SIP'
        elif proto_num == 67 or proto_num == 68:
            return 'DHCP'
        elif proto_num == 53:
            return 'DNS'
        else:
            return 'Unknown'


    def apply_display_filter(self):
        display_filter_expression = self.display_filter_input.text()
        if display_filter_expression:
            # Clear the current packet list
            self.packet_list.clear()

            # Apply the display filter logic
            filtered_packets = [pkt for pkt in self.captured_packets if self.match_display_filter(pkt, display_filter_expression)]

            # Display the filtered packets
            for pkt in filtered_packets:
                self.display_captured_packets(pkt)
        else:
            QMessageBox.warning(self, "Warning", "Please provide a display filter expression.")


    def match_display_filter(self, pkt, display_filter_expression):
        # Check if the display filter expression matches the packet attributes
        if display_filter_expression.lower() == 'tcp':
            # Check if the packet is TCP
            return TCP in pkt
        elif display_filter_expression.lower() == 'udp':
            # Check if the packet is UDP
            return UDP in pkt
        elif display_filter_expression.lower() == 'icmp':
            # Check if the packet is ICMP
            return ICMP in pkt
        elif display_filter_expression.lower() == 'dns':
            # Check if the packet is DNS
            return DNS in pkt
        elif 'source_ip' in display_filter_expression.lower():
            # Extract the source IP address from the display filter expression
            src_ip = display_filter_expression.lower().split('=')[1].strip()
            # Check if the packet's source IP matches the specified source IP
            return IP in pkt and pkt[IP].src == src_ip
        elif 'destination_ip' in display_filter_expression.lower():
            # Extract the destination IP address from the display filter expression
            dst_ip = display_filter_expression.lower().split('=')[1].strip()
        #    Check if the packet's destination IP matches the specified destination IP
            return IP in pkt and pkt[IP].dst == dst_ip
        elif 'source_port' in display_filter_expression.lower():
            # Extract the source port from the display filter expression
            src_port = int(display_filter_expression.lower().split('=')[1].strip())
            # Check if the packet's source port matches the specified source port
            return TCP in pkt and pkt[TCP].sport == src_port
        elif 'destination_port' in display_filter_expression.lower():
            # Extract the destination port from the display filter expression
            dst_port = int(display_filter_expression.lower().split('=')[1].strip())
            # Check if the packet's destination port matches the specified destination port
            return TCP in pkt and pkt[TCP].dport == dst_port
        elif 'length' in display_filter_expression.lower():
            # Extract the packet length from the display filter expression
            length = int(display_filter_expression.lower().split('=')[1].strip())
            # Check if the packet's length matches the specified length
            return len(pkt) == length
        elif 'destination_ip' in display_filter_expression.lower() and 'destination_port' in display_filter_expression.lower():
            # Extract destination IP and port from the display filter expression
            dst_ip = display_filter_expression.lower().split('=')[1].split('and')[0].strip()
            dst_port = int(display_filter_expression.lower().split('=')[2].strip())
            # Check if the packet's destination IP and port match the specified values
            return IP in pkt and pkt[IP].dst == dst_ip and TCP in pkt and pkt[TCP].dport == dst_port
        elif 'source_ip' in display_filter_expression.lower() and 'source_port' in display_filter_expression.lower():
            # Extract source IP and port from the display filter expression
            src_ip = display_filter_expression.lower().split('=')[1].split('and')[0].strip()
            src_port = int(display_filter_expression.lower().split('=')[2].strip())
            # Check if the packet's source IP and port match the specified values
            return IP in pkt and pkt[IP].src == src_ip and TCP in pkt and pkt[TCP].sport == src_port
        elif 'source_ip' in display_filter_expression.lower() and 'destination_port' in display_filter_expression.lower():
            # Extract source IP and destination port from the display filter expression
            src_ip = display_filter_expression.lower().split('=')[1].split('and')[0].strip()
            dst_port = int(display_filter_expression.lower().split('=')[2].strip())
            # Check if the packet's source IP and destination port match the specified values
            return IP in pkt and pkt[IP].src == src_ip and TCP in pkt and pkt[TCP].dport == dst_port
        elif 'destination_ip' in display_filter_expression.lower() and 'source_port' in display_filter_expression.lower():
            # Extract destination IP and source port from the display filter expression
            dst_ip = display_filter_expression.lower().split('=')[1].split('and')[0].strip()
            src_port = int(display_filter_expression.lower().split('=')[2].strip())
            # Check if the packet's destination IP and source port match the specified values
            return IP in pkt and pkt[IP].dst == dst_ip and TCP in pkt and pkt[TCP].sport == src_port
        else:
            # Implement other matching criteria as needed
            return False

    def enable_analyze_button(self):
        if  self.packet_list.selectedItems():
            self.analyze_button.setEnabled(True)
            self.export_button.setEnabled(True)
        else:
            self.analyze_button.setEnabled(False)
            self.export_button.setEnabled(False)

    def analyze_packet(self):
        selected_item = self.packet_list.selectedItems()[0]
        packet_info = [selected_item.text(i) for i in range(11)]
        dialog = PacketAnalyzerDialog(packet_info)
        dialog.exec_()

    def new_file(self):
        # Reset the frame number counter to 1
        self.frame_number_counter = 0
        # Implement creating a new file
        # Clear captured packets list
        self.captured_packets = []

        # Clear packet list display
        self.packet_list.clear()

        # Enable/disable buttons as necessary
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def open_file(self):
        # Implement opening a file
        filename, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP files (*.pcap)")
        if filename:
            self.captured_packets = rdpcap(filename)
            for pkt in self.captured_packets:
                self.display_captured_packets(pkt)

    def save_file(self):
        # Implement saving a file
        if not self.captured_packets:
            QMessageBox.warning(self, "Save Packets", "No packets captured to save.")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Save Packets", "", "PCAP files (*.pcap)")
        if filename:
            wrpcap(filename, self.captured_packets)
            QMessageBox.information(self, "Save Packets", f"Packets saved to {filename}.")

    def save_as_file(self):
        # Implement saving a file with a different name
        if not self.captured_packets:
            QMessageBox.warning(self, "Save Packets", "No packets captured to save.")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Save Packets As", "", "PCAP files (*.pcap)")
        if filename:
            wrpcap(filename, self.captured_packets)
            QMessageBox.information(self, "Save Packets", f"Packets saved to {filename}.")

    def selectFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,"Select PCAP File", "","PCAP Files (*.pcap)", options=options)
        if fileName:
            self.convertToKML(fileName)

    def get_external_ip(self):
        try:
            response = requests.get('https://api64.ipify.org?format=json')
            if response.status_code == 200:
                return response.json()['ip']
        except Exception as e:
            print(f"Error getting external IP: {e}")
        return None

    def retKML(self, dstip, srcip):
        dst = self.ip2location.get_all(dstip)
        src = self.ip2location.get_all(srcip)  # Retrieve geographical information for the source IP
        try:
            dstlongitude = float(dst.longitude)
            dstlatitude = float(dst.latitude)
            srclongitude = float(src.longitude)
            srclatitude = float(src.latitude)
            kml = (
                '<Placemark>\n'
                '<name>%s</name>\n'
                '<extrude>1</extrude>\n'
                '<tessellate>1</tessellate>\n'
                '<styleUrl>#transBluePoly</styleUrl>\n'
                '<LineString>\n'
                '<coordinates>%f,%f\n%f,%f</coordinates>\n'
                '</LineString>\n'
                '</Placemark>\n'
            ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
            return kml
        except Exception as e:
            print(f"Error generating KML: {e}")
            return ''

    def plotIPs(self, pcap, srcip):
        kmlPts = ''
        for (ts, buf) in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                dst = socket.inet_ntoa(ip.dst)
                KML = self.retKML(dst, srcip)
                kmlPts += KML
            except:
                pass
        return kmlPts

    def convertToKML(self, pcapFileName):
        self.ip2location = IP2Location('/home/diablo/geosniffx/IP2LOCATION/IP2LOCATION-LITE-DB11.BIN') #add your database location for geodecoding 
        try:
            with open(pcapFileName, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n' \
                            '<Style id="transBluePoly">' \
                            '<LineStyle>' \
                            '<width>1.5</width>' \
                            '<color>501400E6</color>' \
                            '</LineStyle>' \
                            '</Style>'
                kmlfooter = '</Document>\n</kml>\n'
                srcip = self.get_external_ip()
                if srcip:
                    kmldoc = kmlheader + self.plotIPs(pcap, srcip) + kmlfooter
                    kmlFileName, _ = QFileDialog.getSaveFileName(self, 'Save KML File', '', 'KML Files (*.kml)')
                    if kmlFileName:
                        with open(kmlFileName, 'w') as kmlFile:
                            kmlFile.write(kmldoc)
                        print("KML file saved successfully.")
        except Exception as e:
            print(f"Error converting PCAP to KML: {e}")

    def open_google_maps(self):
        url = "https://www.google.com/maps/d/u/0/?hl=en"
        webbrowser.open_new_tab(url)


class PacketAnalyzerDialog(QDialog):
    def __init__(self, packet_info):
        super().__init__()
        self.setWindowTitle("Packet Analyzer")
        self.setGeometry(300, 300, 600, 400)  # Set initial size

        # Set the background image
        self.set_background_image("/home/diablo/geosniffx/Preview.png")  # Provide the path to your image

        layout = QVBoxLayout()

        label = QLabel("Packet Details:")
        layout.addWidget(label)

        packet_details = QGridLayout()

        labels = ["Time:", "Frame Number:", "Source IP:", "Destination IP:",
                  "Source Port:", "Destination Port:", "Protocol:", "Length:", "Source MAC:", "Destination MAC:","info :"]



        for row, label_text in enumerate(labels):
            label = QLabel(label_text)
            value = QLabel(packet_info[row] if row < len(packet_info) else "N/A")
            packet_details.addWidget(label, row, 0)
            packet_details.addWidget(value, row, 1)

        layout.addLayout(packet_details)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        layout.addWidget(ok_button, alignment=Qt.AlignRight)

        self.setLayout(layout)

        # Apply style sheet
        self.setStyleSheet("""
            QLabel {
                color: #FFF;
            }
            QPushButton {
                background-color: #1B2631;
                color: #FFF;
                border: 1px solid #1B4F72;
                border-radius: 4px;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #005D7A;
                border: 1px solid #005D7A;
            }
            QPushButton:pressed {
                background-color: #004A5F;
                border: 1px solid #004A5F;
            }
        """)

    def set_background_image(self, image_path):
        # Set the background image of the dialog
        image = QImage(image_path)
        palette = QPalette()
        palette.setBrush(QPalette.Background, QBrush(image))
        self.setPalette(palette)



def get_protocol_name(proto_num):
    if proto_num == 6:
        return 'TCP'
    elif proto_num == 17:
        return 'UDP'
    elif proto_num == 1:
        return 'ICMP'
    elif proto_num == 20 or proto_num == 21:
        return 'FTP'
    elif proto_num == 25:
        return 'SMTP'
    elif proto_num == 110:
        return 'POP3'
    elif proto_num == 143:
        return 'IMAP'
    elif proto_num == 161:
        return 'SNMP'
    elif proto_num == 22:
        return 'SSH'
    elif proto_num == 23:
        return 'Telnet'
    elif proto_num == 5060 or proto_num == 5061:
        return 'SIP'
    elif proto_num == 67 or proto_num == 68:
        return 'DHCP'
    elif proto_num == 53:
        return 'DNS'
    else:
        return 'Unknown'

if __name__ == "__main__":
    app = QApplication(sys.argv)
    welcome_window = WelcomeWindow()
    welcome_window.show()
    sys.exit(app.exec_())
