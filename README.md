# NexScan
Yes, you should add a `README.md` file to explain how to use your project. Here’s a basic `README.md` template for **NexScan**:

---

## **NexScan - Advanced Vulnerability Scanner**

NexScan is an automated vulnerability scanner that gathers information about a target website or IP address, identifies potential security issues, and detects outdated software.

### **Features**
- Identifies technologies using **WhatWeb**
- Resolves IP addresses
- Runs **Nmap** with vulnerability detection
- Extracts CVE information from Nmap results
- Checks for missing **security headers**
- Detects outdated **server software**

### **Installation**
Ensure required dependencies are installed:
```bash
sudo apt update
sudo apt install nmap whatweb python3-pip
pip3 install requests beautifulsoup4
```

### **Usage**
#### **Scan a Website**
```bash
python3 NexScan.py https://example.com
```
- Detects technologies
- Resolves IP address
- Scans for vulnerabilities
- Checks for missing security headers
- Detects outdated software

#### **Scan an IP Address**
```bash
python3 NexScan.py -i 192.168.1.1
```
- Runs **Nmap** vulnerability scan on the target IP.

### **Example Output**
```
[*] Running WhatWeb...
[+] Detected Technologies: Apache, PHP

[+] IP Address: 192.168.1.10

[*] Running Nmap Vulnerability Scan...
[+] Found CVEs:
 - CVE-2021-41773
 - CVE-2020-11975

[-] X-XSS-Protection is missing!
[+] Server: Apache/2.2 (Outdated)
```

### **Contributing**
Feel free to submit issues or contribute improvements to NexScan.

---
