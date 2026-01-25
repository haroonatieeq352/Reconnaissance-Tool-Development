# Reconnaissance-Tool-Development

## 📌 Overview
**Reconnaissance Tool** is a lightweight, modular automation tool developed for **offensive security and penetration testing**.  
It automates initial information gathering by performing both **passive and active reconnaissance**, helping security testers follow real-world **red team workflows** efficiently.

This tool was developed as part of a **Summer Internship – Offensive Security** task.

---

## 🚀 Features

### 🔹 Passive Reconnaissance
- WHOIS lookup  
- DNS enumeration (A, MX, TXT, NS records)  
- Subdomain enumeration using external sources (e.g., crt.sh)

### 🔹 Active Reconnaissance
- Port scanning  
- Banner grabbing  
- Basic service / technology detection

### 🔹 Reporting
- Generates structured reconnaissance output  
- Includes timestamps and IP resolution details  
- Results are saved in the `reports/` directory

### 🔹 Modularity
- Each module runs independently  
- CLI-based execution using command-line flags  
- Logging with verbosity levels

---

## 🛠️ Requirements
- Python 3.x  
- Linux-based system (recommended)

### Required Python Modules
- argparse  
- requests  
- socket  
- subprocess  

---

## 📥 Installation & Usage

### Clone the Repository

- git clone https://github.com/haroonatieeq352/Reconnaissance-Tool-Development.git
- cd Reconnaissance-Tool-Development
- chmod +x reconx.py
- ./reconx.py -h


## 🧪 Example Usage
- ./reconx.py --whois example.com
- ./reconx.py --dns example.com
- ./reconx.py --subdomains example.com
- ./reconx.py --all example.com
