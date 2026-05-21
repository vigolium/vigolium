# Banking Penetration Testing Methodology

> This case study is anonymized and presented for educational purposes in authorized security testing contexts only.

> Based on analysis of 22,132 real WooYun cases

## 1. Banking Attack Surface Layered Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Layer 1: Internet Boundary                          │
├─────────────────────────────────────────────────────────────────────────┤
│  Online Banking │ Mobile Banking │ WeChat Banking │ Direct Banking │    │
│  Credit Card Center │ Official Site / Campaign Pages                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    |
┌─────────────────────────────────────────────────────────────────────────┐
│                   Layer 2: Interface / Channel Layer                     │
├─────────────────────────────────────────────────────────────────────────┤
│  Payment Interface │ Card Network Channel │ Quick Pay │ Direct Debit │  │
│  Aggregated Payment │ Open Banking API                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    |
┌─────────────────────────────────────────────────────────────────────────┐
│                     Layer 3: Internal Systems Layer                      │
├─────────────────────────────────────────────────────────────────────────┤
│  Core Banking │ Loan System │ Risk Control │ AML │ CRM │ Reporting     │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. High-Risk Vulnerability Types

### Tier 1: Financial Vulnerabilities (68-88% High Severity)

| Vulnerability Type | High Severity % | Banking-Specific Scenario |
|-------------------|----------------|--------------------------|
| Password Reset | 88.0% | Online/mobile banking login password, transaction PIN |
| Withdrawal Flaws | 83.1% | Transfer limit bypass, withdrawal validation defects |
| Amount Tampering | 83.0% | Transfer amount, investment amount, repayment amount |
| Payment Flaws | 68.7% | Quick pay, direct debit, interbank transfer |

### Payment Vulnerability Detection (1,056 Cases)

**Manual Testing Checklist**:
```
1. Modify amount parameter: amount=0.01 (test server-side validation)
2. Modify quantity to negative: quantity=-1 (negative transfer)
3. Replay a successful payment request (test idempotency)
4. Concurrent submission of the same order (race condition)
5. Modify payee account/user ID (unauthorized transfer)
6. Tamper with callback notification (forge payment success)
```

**Key Parameters**:
- `amount` / `price` / `total` -> Amount fields
- `to_account` / `payee_id` -> Payee
- `sign` / `signature` -> Signature

**Bypass Techniques**:
```
Negative value attack: Transfer amount = -1000
Decimal overflow: amount = 0.001
Race condition: Multi-threaded concurrent transfers
Status tampering: Modify status=SUCCESS
Signature bypass: Delete/empty the signature field
```

### Tier 2: Authentication and Authorization

| Vulnerability Type | Case Count | Attack Scenario |
|-------------------|-----------|----------------|
| Weak Credentials | 7,513 | Online banking admin panel, operations systems |
| Authorization Bypass | 1,705 | Viewing other users' account information |
| Verification Code | 334 | Login, transfer, password reset |

## 3. Banking-Specific Attack Surfaces

### 1. Mobile Banking App Security

```
Client-Side Security
├── Anti-decompilation protection (hardening strength)
├── Local storage (sensitive information)
├── Log leakage
└── Certificate validation (SSL Pinning)

Communication Security
├── Encryption algorithms (hardcoded keys)
├── Request signing (algorithm reverse engineering)
└── Replay attacks

Business Logic
├── Login authentication (password/fingerprint/face)
├── Transaction verification
└── Transfer limits
```

**App Penetration Approach**:
```
1. Packet capture: Bypass SSL Pinning (Frida/Objection)
2. Reverse engineering: Unpack -> Signing algorithm reversal -> Key extraction
3. Hook testing: Bypass face/fingerprint verification, modify limit checks
```

### 2. Online Banking Systems

```
Attack approach:
├── ActiveX control vulnerabilities
├── Frontend encryption bypass (JS reverse engineering)
├── Password control bypass
├── USB token driver vulnerabilities
├── Bulk transfer interface authorization bypass
└── Statement/receipt unauthorized download
```

### 3. Third-Party Payment Interfaces

```
Attack points:
├── Merchant key leakage (GitHub search)
├── Callback signature verification flaws
├── Async notification replay
├── Amount validation missing
└── Merchant ID authorization bypass
```

## 4. Verification Bypass Techniques

### SMS Verification Code
```
├── Brute force (4-6 digits, feasible)
├── Concurrency (bypass attempt limits)
├── Reuse (same code used multiple times)
├── Echo (code returned in response)
└── Universal codes (0000/1234)
```

### Facial Recognition
```
├── Photo attack
├── Video attack
├── Hook return values
├── Interface replay
└── Replace facial data
```

### Transaction Signatures
```
├── Hardcoded signing key
├── Critical fields not signed
├── Signature verification optional
└── Signature downgrade attack
```

## 5. Penetration Paths

### Path 1: External Web Breach
```
Information gathering -> Subdomains/Ports/Fingerprinting
    |
Vulnerability exploitation (priority order):
├── 1. Weak credential brute force
├── 2. Struts2/WebLogic RCE
├── 3. Business logic vulnerabilities
└── 4. File upload / SQL injection
```

### Path 2: Mobile Endpoint Breach
```
Static analysis -> Decompile, key search, API extraction
Dynamic analysis -> Bypass Pinning, packet capture, Hook
Business testing -> Login/Transfer/Password reset
```

### Path 3: Supply Chain Attack
```
Outsourcing company -> Code/environment leakage
Equipment vendor -> Preset accounts
Service provider -> SMS/identity verification
```

## 6. High-Value Targets

| Target System | Value | What Can Be Achieved |
|--------------|-------|---------------------|
| Core Banking | Critical | Account balances, transaction records |
| Loan System | High | Loan approval, credit limit adjustment |
| Risk Control System | High | Blocklists, rule configuration |
| CRM System | Medium | KYC documentation |

## 7. Practical Checklist

### Information Gathering
- [ ] Subdomain enumeration
- [ ] GitHub code leakage search
- [ ] App download and analysis
- [ ] WeChat official account / mini-program interface discovery

### Vulnerability Detection
- [ ] Weak credential testing
- [ ] Business logic (payment/transfer/password reset)
- [ ] Authorization bypass testing
- [ ] Interface security (signing/encryption)
- [ ] App client-side security

### Deep Exploitation
- [ ] Payment amount tampering
- [ ] Verification code bypass
- [ ] Facial recognition bypass
- [ ] Concurrent race conditions

---

**Reference methodologies**:
- See {baseDir}/references/logic-flaws.md (payment tampering, authorization bypass) and {baseDir}/references/sql-injection.md (injection techniques) for related methodology.

**Representative case patterns**:
- A major bank's system vulnerability leading to shell access (affecting third-party payment integrations)
- An education platform leading to a foundation system (allowing donation amount tampering)
