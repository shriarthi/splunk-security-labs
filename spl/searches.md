# SPL Queries Catalog
This document contains SPL queries for analyzing the two sample log sources:

- `sample_weblogs.log`  →  sourcetype = **access_combined**
- `sample_security.log` →  sourcetype = **linux_secure**

Each query includes an explanation and typical use-case.

---

## 1. Web Logs (Apache / NGINX)

### **1.1 Top 20 IP addresses by request volume**
```
index=web sourcetype=access_combined
| stats count AS requests by clientip
| sort - requests
| head 20
```
**Use-case:** Identify heavy users, scanners, bots, or brute-force behavior.

---

### **1.2 Detect HTTP errors (4xx / 5xx)**
```
index=web sourcetype=access_combined
| search status>=400
| stats count by status, clientip
| sort - count
```
**Use-case:** Find misconfigurations, broken pages, or attack traffic.

---

### **1.3 Detect brute-force login attempts (web login endpoint)**
```
index=web sourcetype=access_combined "POST /login"
| stats count BY clientip, status
| where count > 5 AND status=401
```
**Use-case:** Detect repeated failed login attempts.

---

### **1.4 Suspicious User-Agent detection (bots / scanners)**
```
index=web sourcetype=access_combined
| where like(useragent, "%curl%")
    OR like(useragent, "%python%")
    OR like(useragent, "%wget%")
    OR useragent="-"
| stats count by clientip, useragent
```
**Use-case:** Identify non-browser/scanner traffic.

---

### **1.5 URI with the most hits**
```
index=web sourcetype=access_combined
| stats count BY request
| sort - count
```
**Use-case:** Identify high-interest endpoints or attack targets.

---

---

## 2. Security Logs (Linux auth.log)

### **2.1 Successful logins**
```
index=security sourcetype=linux_secure "Accepted password"
| stats count BY host, process, clientip
```
**Use-case:** Track valid user access.

---

### **2.2 Failed SSH logins**
```
index=security sourcetype=linux_secure "Failed password"
| rex field=message "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip
| sort - count
```
**Use-case:** Identify brute-force attempts or password guessing.

---

### **2.3 Failed vs successful login ratio**
```
index=security sourcetype=linux_secure ("Failed password" OR "Accepted")
| eval status=if(like(message,"%Failed%"),"failed","success")
| stats count BY status
```
**Use-case:** Authentication security health check.

---

### **2.4 Sudo command usage**
```
index=security sourcetype=linux_secure "sudo:"
| rex field=message "COMMAND=(?<command>.*)"
| stats count BY command, host
| sort - count
```
**Use-case:** Track privilege escalation activity.

---

### **2.5 Detect repeated SSH failures from same IP**
```
index=security sourcetype=linux_secure "Failed password"
| rex field=message "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip
| where count > 3
```
**Use-case:** Flag brute-force attempts.

---

### **2.6 Detect root login attempts**
```
index=security sourcetype=linux_secure
| search "Failed password for root" OR "Accepted password for root"
```
**Use-case:** Identify root login attempts (good or bad).

---

### **2.7 Detect privilege escalation via sudo**
```
index=security sourcetype=linux_secure "sudo:"
| stats count BY user, host
```
**Use-case:** Monitor admin-level changes.

---

## 3. Combined (Correlation Searches)

### **3.1 Web brute-force leading to SSH attempt (multi-step attack)**
```
(index=web sourcetype=access_combined "POST /login" status=401)
OR
(index=security sourcetype=linux_secure "Failed password")
| rex field=message "from\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip
| where count > 10
```
**Use-case:** Detect attacker pivoting from web login attempts to SSH login attempts.

---

### **3.2**
