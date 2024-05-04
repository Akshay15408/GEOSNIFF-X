GEOSNIFFX - Geographic Packet Sniffer
GEOSNIFFX is a Python-based packet sniffer with geographic visualization capabilities. It provides a user-friendly interface for capturing, analyzing, and exporting network packets, along with the ability to visualize packet routes on Google Earth.

Key Features
Packet Capture: Capture network packets from selected interfaces.
Packet Analysis: Analyze captured packets and view detailed packet information.
Export Functionality: Export captured packets to various file formats such as PCAP, CSV, JSON, and TCPDump.
Geographic Visualization: Convert captured packets to KML format for visualization in Google Earth.
Filtering: Apply display filters to view specific packets based on user-defined criteria.
Integrated Help: Access an integrated help page for guidance on using GEOSNIFFX.
Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

Prerequisites
Before running GEOSNIFFX, ensure you have the following dependencies installed:

Python 3.x
PyQt5
dpkt
IP2Location (optional, for geographic visualization)
You can install the required dependencies using the following command:

bash
Copy code
pip install -r requirements.txt
Installing
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/yourusername/GEOSNIFFX.git
Navigate to the project directory:

bash
Copy code
cd GEOSNIFFX
Run the GEOSNIFFX.py script to launch the application:

bash
Copy code
python GEOSNIFFX.py
Usage
Start capturing packets from the desired network interface.
Analyze, export, and visualize captured packets as needed.
Refer to the integrated help page for assistance with various features.
