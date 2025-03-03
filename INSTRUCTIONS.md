# Vo1d Botnet Detection Tool – Instructions

## 📌 Overview

This repository contains:
- **`vo1dbot_scanner.py`** – A Python script for detecting potential Vo1d botnet activity on Android TV devices.
- **`Vo1d_Botnet_Research_Report.docx`** – A detailed research report explaining the methodology and findings behind this project.

The tool monitors live network traffic, detects suspicious activities, and provides real-time alerts.

---

## 🛠️ Installation & Setup

### 1️⃣ Prerequisites
Ensure you have:
- **Python 3.x** installed on your system.
- Administrative privileges to capture network packets.
- Required dependencies installed.

### 2️⃣ Install Dependencies
Run the following command:

```bash
pip install pyshark scapy
```

### 3️⃣ Run the Detection Tool
Use the following command to start monitoring network traffic:

```bash
sudo python vo1dbot_scanner.py
```

> 🔹 **Note**: Replace `"eth0"` with the appropriate network interface (e.g., `"wlan0"` for Wi-Fi users).

---

## 🔍 How It Works

The script captures and analyzes network traffic, looking for:
- **Suspicious DNS Queries** (possible DGA-generated domains).
- **Connections to Known Command-and-Control (C2) Servers**.
- **Traffic on Unusual Ports** (e.g., 55503, 55600).
- **High Outbound Connection Activity**, suggesting proxy misuse.

🚨 **Real-time alerts** will be displayed if any suspicious activity is detected.

---

## ⚠️ Limitations & Future Improvements

🚧 **This tool is experimental and has not been tested in large-scale environments.**

### Potential Enhancements:
- Advanced anomaly detection using **machine learning**.
- Integration with **threat intelligence feeds** for real-time updates.
- Automated **firewall rules** to block malicious connections.

---

## 🏛️ Ethical Considerations

🔴 **Use this tool responsibly and ethically:**
- It should **only** be used to monitor networks you own or have permission to analyze.
- The results may include **false positives**, so manual verification is recommended.
- This tool is intended **for defensive purposes only**, not for exploitation.

---

## 📢 Contributing & Feedback

I am not a cybersecurity expert but would love to improve this project! 

If you have suggestions:
1. **Open an issue** on this repository.
2. **Submit a pull request** with improvements.
3. **Join discussions** on GitHub.

Your feedback is greatly appreciated! 🚀

---

## 📜 License

This project is licensed under the **MIT License**. You are free to use and modify it, but I take no responsibility for any misuse.
