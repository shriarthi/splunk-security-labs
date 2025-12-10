# Alerts Catalog
This file contains alerting use-cases for Splunk based on the sample logs.

Each alert includes:
- SPL query
- Trigger condition
- Severity
- Description

---

## 1. Web Log Alerts (sample_weblogs.log)

### **1.1 Repeated Failed Login Attempts**
```
index=web sourcetype=access_combined "POST /login" status=401
| stats count BY clientip
| where count > 5
```
**Trigger:** More than 5 failures in 5 minutes  
**Severity:** High  
**Purpose:** Detect brute-force login attempts.

---

### **1.2 Suspicious User-Agent Detected**
```
index=web sourcetype=access_combined
| search useragent="curl*" OR useragent="python*" OR useragent="wget*" OR useragent="-"
```
**Trigger:** Any match  
**Severity:** Medium  
**Purpose:** Detect scanners or bots.

---

### **1.3 Access to restricted/admin endpoints**
```
index=web sourcetype=access_combined
| search request="/admin" OR request="/phpmyadmin" OR request="/wp-login.php"
```
**Trigger:** Any hit  
**Severity:** High  
**Purpose:** Detect reconnaissance or attempted exploitation.

---

---

## 2. Security Log Alerts (sample_security.log)

### **2.1 SSH Brute Force**
```
index=security sourcetype=linux_secure "Failed password"
| rex field=message "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip
| where count > 5
```
**Trigger:** >5 failures from same IP  
**Severity:** Critical  
**Purpose:** Detect password-guessing attacks.

---

### **2.2 Successful Root Login**
```
index=security sourcetype=linux_secure "Accepted password for root"
```
**Trigger:** Any successful root login  
**Severity:** Critical  
**Purpose:** Detect unauthorized root access.

---

### **2.3 Sudden Spike in Sudo Commands**
```
index=security sourcetype=linux_secure "sudo:"
| timechart span=5m count
| where count > 10
```
**Trigger:** >10 sudo commands in 5 minutes  
**Severity:** High  
**Purpose:** Detect possible privilege escalation or malicious activity.

---

### **2.4 AppArmor / Kernel Security Denials**
```
index=security sourcetype=linux_secure ("apparmor=\"DENIED\"" OR "audit:")
```
**Trigger:** Any  
**Severity:** Medium  
**Purpose:** Detect restricted actions, possibly an attacker probing privileges.

---

---

## 3. Correlation Alerts (multi-log detection)

### **3.1 IP involved in both Web and SSH failures**
```
(index=web sourcetype=access_combined status=401 "POST /login")
OR
(index=security sourcetype=linux_secure "Failed password")
| rex field=message "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip
| where count > 10
```
**Trigger:** >10 failures combined  
**Severity:** Critical  
**Purpose:** Detect attacker pivoting from web → server.

---

### **3.2 Multiple failed login types in short time window**
```
(index=web sourcetype=access_combined status=401)
OR
(index=security sourcetype=linux_secure "Failed password")
| stats count BY host
| where count > 20
```
**Trigger:** >20 failures in 10 minutes  
**Severity:** High  
**Purpose:** Detect distributed or coordinated attack.

---

## End of File
