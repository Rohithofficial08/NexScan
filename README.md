# NexScan
just a NexScan

Here's how you can use **NexScan** to scan for vulnerabilities:

### **Installation**
First, make sure you have the necessary dependencies installed:
```bash
sudo apt update
sudo apt install nmap whatweb python3-pip
pip3 install requests beautifulsoup4
```

### **Usage Examples**
1. **Scan a Website**
   ```bash
   python3 NexScan.py https://example.com
   ```
   This will:
   - Identify technologies using **WhatWeb**
   - Resolve the IP address
   - Run **Nmap** with vulnerability detection
   - Check for missing **security headers**
   - Detect outdated **server software**

2. **Scan a Specific IP**
   ```bash
   python3 NexScan.py -i 192.168.1.1
   ```
   This will:
   - Run **Nmap** on the specified IP to detect vulnerabilities.
