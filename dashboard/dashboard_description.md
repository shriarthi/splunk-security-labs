# Security & Web Analytics Dashboard

This dashboard provides unified visibility into both **web activity** and **security events**, using data from:

- `sample_weblogs.log` (Apache/NGINX-style logs)
- `sample_security.log` (Linux authentication and system logs)

It is designed for SIEM-style monitoring and includes the following visual panels:

---

## 📊 Web Traffic Analytics

### **1. Total Web Requests**
Shows the total count of processed HTTP requests to monitor traffic volume.

### **2. HTTP Status Distribution**
Pie chart showing:
- Successful responses (200s)
- Redirects (300s)
- Client errors (400s)
- Server errors (500s)

### **3. Top Client IP Addresses**
Table listing the most active source IPs accessing the web server.

### **4. Top Requested URIs**
Highlights the most frequently accessed endpoints, useful for:
- Usage analysis
- Identifying scanning behavior
- Detecting high-risk pages

---

## 🔐 Security Event Analytics

### **5. Failed Logins**
Pulls authentication failures from Linux system logs, showing:
- Host
- Process (sshd, sudo, etc.)
- Message

Useful for detecting bad passwords or misconfigurations.

### **6. Possible SSH Brute-Force Attempts**
Detects repeated authentication failures from the same IP.
Triggered when:
- `count > 5` failed attempts

This helps identify malicious brute-force behavior.

---

## 📁 File Locations
