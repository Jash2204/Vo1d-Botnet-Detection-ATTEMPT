# Vo1d-Botnet-Detection-ATTEMPT
Python-based tool to detect potential Vo1d botnet infections on Android TV using network traffic analysis. Identifies suspicious DNS queries, C2 connections, and unusual ports. Developed by a university student with ChatGPT’s help—seeking cybersecurity experts for further development and improvements.

Overview
This repository contains research and a Python-based tool designed to detect potential Vo1d botnet infections on Android TV devices using network traffic analysis.

🚨 Disclaimer: I am not a cybersecurity expert. I am a university student who read about the Vo1d botnet in the news and wanted to develop something that could potentially help affected users. This project was created with the assistance of ChatGPT and based on publicly available cybersecurity research. If you are an expert in this field, I would greatly appreciate any feedback to improve the detection methods.

Features
Live Network Traffic Monitoring using PyShark and Scapy.
Detection of Suspicious Activity, including:
High-entropy domain queries (potential DGA domains used by Vo1d botnet).
Connections to known Command-and-Control (C2) servers.
Traffic on unusual ports (e.g., 55503, 55600).
Excessive outbound connections suggesting proxy misuse.
Real-time Alerts when suspicious network behaviors are detected.
How It Works
The tool continuously captures network packets and checks them against known Indicators of Compromise (IoCs).

Indicators of Vo1d Botnet Activity:
Unusual DNS Queries – Botnets often use Domain Generation Algorithms (DGA) to avoid detection. The tool analyzes DNS entropy to flag suspicious queries.
C2 Communications – Attempts to connect to known Vo1d botnet servers.
Uncommon Port Usage – The Vo1d botnet has been observed communicating over high, non-standard ports.
Frequent Proxy Activity – If a device is relaying large amounts of traffic to multiple IPs, it could be acting as part of the botnet's proxy network.
Installation & Usage
Prerequisites:

Python 3.x
pyshark (for live packet capture)
scapy (for deep packet analysis)
Administrative privileges (for packet sniffing)
Installation:
pip install pyshark scapy
Running the Detection Tool:
sudo python android_tv_botnet_scan.py
Note: Replace eth0 with your network interface if needed (e.g., wlan0 for Wi-Fi users).

Limitations & Future Improvements
🚧 This tool is experimental and has not been tested in large-scale environments.

Possible Enhancements:
Improved Anomaly Detection: Use machine learning to detect evolving botnet patterns.
Integration with Threat Intelligence Feeds for real-time IoC updates.
Automated Blocking: Implement firewall rules to block suspicious connections.
Responsible Use & Ethical Considerations
🔴 This tool is for educational and defensive purposes only.

It should not be used to monitor networks without permission.
It is intended to help users protect their own devices, not to attack or exploit vulnerabilities.
Results may include false positives, so manual verification is advised.
Contributing & Feedback
As I am not an expert in cybersecurity, I welcome any feedback or contributions! If you have suggestions for improvement, please:

Open an issue on this repository.
Submit a pull request with suggested changes.
Reach out via GitHub discussions.
Your insights would be invaluable in refining this project. 🚀

Acknowledgments
This project was inspired by news reports on the Vo1d botnet.
ChatGPT assisted in structuring this research and developing the code.
Open-source cybersecurity research contributed to the detection methodologies.
License
📜 This project is licensed under the MIT License, meaning you are free to use and modify it, but I take no responsibility for any misuse or unintended consequences.
