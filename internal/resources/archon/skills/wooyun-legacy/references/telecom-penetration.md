# Telecom Carrier Penetration Testing Methodology

> This case study is anonymized and presented for educational purposes in authorized security testing contexts only.

> Based on analysis of 22,132 real WooYun cases

## 1. Attack Surface Overview

```
                     Telecom Carrier Attack Surface
                              │
    ┌─────────┬─────────┬─────┴─────┬─────────┬─────────┐
    |         |         |           |         |         |
 Internet   Mobile    Value-Added Internal    IoT     Supply
 Portal     Apps      Services   Systems   Platform  Chain
    │         │         │           │         │         │
 ├─Web      ├─App     ├─SP/CP    ├─OA      ├─IoT    ├─Outsourced
 │ Portal   │         │ Platform  │         │ Cards   │ Vendors
 ├─Loyalty  ├─H5     ├─SMS      ├─Email   ├─M2M    ├─Equipment
 │ Points   │         │ Gateway   │         │        │ Vendors
 └─Campaign └─SDK    └─Billing  └─VPN     └─Connected└─Ops
   Pages              Interface             Vehicles   Vendors
```

## 2. Common Vulnerability Types

### 1. Weak Credentials (7,513 Cases, 58.2% High Severity)

| Target System | Common Weak Credentials | Shell Access Likelihood |
|--------------|------------------------|----------------------|
| BOSS Admin Panel | admin/admin, employee_id/123456 | Very High |
| Network Management Platform | root/root, vendor defaults | Very High |
| Databases | sa/(empty), root/root | Very High |
| Docker API | No authentication | Very High |

**Detection Method**:
```bash
# Bulk brute force
hydra -L users.txt -P top1000.txt target ssh
hydra -l admin -P passwords.txt target http-post-form
```

### 2. Authorization Bypass (1,705 Cases, 62.3% High Severity)

**Telecom-Specific Authorization Bypass Points**:

| Functionality | Key Parameter | Impact |
|--------------|--------------|--------|
| Bill inquiry | `phone`, `mobile` | View any user's bill |
| Call records | `cust_id`, `user_id` | Obtain any user's call records |
| Plan changes | `order_id` | Modify another user's plan |
| Identity verification info | `id_card` | Leak ID card photos |

**Bypass Techniques**:
```
Parameter pollution: ?uid=1&uid=2 (takes the latter)
Array injection: uid[]=target_id
JSON nesting: {"user":{"id":target_id}}
```

### 3. Unauthorized Access (1,891 Cases, 58.2% High Severity)

**High-Frequency Exposed Paths**:
```
/admin           -> Admin panel
/api/swagger     -> API documentation
/console         -> Console
/manager         -> Tomcat manager
/zabbix          -> Monitoring system
```

## 3. Uncommon But High-Value Attack Surfaces

### 1. SP/CP Value-Added Service Platforms
- Third-party integrations, often with lower security requirements
- Directly connected to billing systems
- Entry points: SMS/MMS distribution platforms, data top-up interfaces

### 2. IoT Card Management Platforms
- IoT device management admin panel
- Bulk provisioning interfaces
- M2M platform APIs

### 3. Network Management Systems (NMS)
- Vendor-specific management platforms (e.g., U2000/M2000)
- Environmental monitoring systems
- Once breached, can control core network equipment

## 4. Shell Access Achievement Paths

### Path 1: Web RCE
```
Priority order:
1. Struts2 RCE (S2-045/046/048/052)
2. WebLogic deserialization
3. Shiro deserialization (rememberMe)
4. Fastjson RCE
5. File upload bypass
6. SQL injection -> xp_cmdshell/into outfile
```

### Path 2: Boundary Device Breach
```
VPN device vulnerabilities:
├── Pulse Secure CVE-2019-11510
├── Fortinet CVE-2018-13379
├── Citrix CVE-2019-19781
└── Various vendor-specific VPN password reset flaws

Network devices:
├── Vendor default passwords
├── Cisco Smart Install protocol abuse
└── SNMP community string leakage
```

### Path 3: Supply Chain Attack
```
Third-party outsourcing company -> Dev/test environment -> Production environment
Operations staff workstation -> Lateral movement into internal network
```

## 5. Lateral Movement Targets

| Target System | Value | Difficulty |
|--------------|-------|-----------|
| BOSS System | User data, billing control | High |
| AAA Authentication Center | Network-wide user credentials | High |
| SMS Gateway | SMS interception | High |
| Core Network Equipment | Network control plane | Very High |
| DNS Servers | Traffic hijacking | Medium |

## 6. Practical Checklist

### Information Gathering
- [ ] Subdomain enumeration (carrier web properties)
- [ ] Port scanning (non-standard ports)
- [ ] GitHub/code repository leakage search
- [ ] Network space mapping (Shodan/Fofa)

### Vulnerability Discovery
- [ ] Weak credential brute force
- [ ] Authorization bypass testing (phone number/user ID enumeration)
- [ ] Unauthorized access testing
- [ ] Framework vulnerability scanning

### Post-Shell Activities
- [ ] Persistence
- [ ] Internal network information gathering
- [ ] Credential harvesting
- [ ] Proxy tunneling
- [ ] Lateral movement

---

**Reference methodologies**:
- See {baseDir}/references/unauthorized-access.md (weak credentials, service exposure) and {baseDir}/references/info-disclosure.md (reconnaissance) for related methodology.
