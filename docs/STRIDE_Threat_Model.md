# AST Smart Asset Management - STRIDE Threat Model

**Project:** Project 3: Smart Asset Inventory & Predictive Maintenance (AST)  
**Institution:** Badr University in Assiut (BUA DevHub Field Phase - Squad 3)  
**Standard:** Microsoft STRIDE Methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. System Architecture & Trust Boundaries

The AST ecosystem spans four distinct execution tiers:
1. **Client Tier:** Flutter Cross-Platform Mobile Client (Android/iOS) operated by technicians and auditors.
2. **Gateway Tier:** Node.js/Express/Prisma REST API Gateway exposing endpoints AST-FR-01 through AST-FR-10.
3. **Storage Tier:** PostgreSQL 16 Relational Database housing the 12-table relational schema and append-only audit event logs.
4. **Analytics Tier:** Python FastAPI Predictive Maintenance AI microservice.

### Trust Boundaries:
- **TB-1 (Internet / Untrusted Network -> API Gateway):** Protects public interfaces with TLS 1.3, rate limiting, and CORS.
- **TB-2 (API Gateway -> PostgreSQL Database):** Protects internal database connection with parameter binding and private Docker networking.
- **TB-3 (API Gateway -> AI Microservice):** Internal microservice communication validated via private subnets and schema verification.
- **TB-4 (Mobile App -> Physical World):** Optical barcode and QR scanning verification.

```mermaid
flowchart TD
    User([Technician / Auditor]) -->|HTTPS / TLS 1.3 [TB-1]| Gateway[API Gateway / Express]
    Gateway -->|Parameterized Queries [TB-2]| DB[(PostgreSQL 16)]
    Gateway -->|Private Network [TB-3]| AI[FastAPI AI Microservice]
    User -->|Camera Scan [TB-4]| QR[Physical Asset QR Tag]
```

---

## 2. STRIDE Threat Matrix & Mitigations

### 2.1 Spoofing (Identity Deception)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-S-01** | Adversary attempts credential brute force against `/auth/login` | API Gateway | High | Rate limiting (max 5 requests per 15 minutes per IP), bcrypt password hashing with salt rounds = 12, account lockout flags. |
| **TH-S-02** | Forged or stolen JWT access token used to impersonate facility manager | API Gateway | Critical | Cryptographic signature verification, short-lived tokens (15m expiry), refresh token rotation. |
| **TH-S-03** | Malicious actor prints replica QR code for non-existent asset | Mobile App & Scanner | Medium | Cryptographic signature embedded in QR tag payload; verification check against authoritative database registry. |

---

### 2.2 Tampering (Data Modification)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-T-01** | SQL Injection via search filters or asset tag query parameters | Database / Prisma | Critical | Complete elimination of raw concatenated queries; strict Prisma ORM parameterized statements and Pydantic/Zod DTO validation. |
| **TH-T-02** | Technician alters historical work order downtime or completion cost | API Gateway / Database | High | Immutable append-only audit logging table (`asset_events`); once a work order is `completed`, update operations are prohibited by business logic. |
| **TH-T-03** | Adversary alters model weights or training telemetry to suppress risk alerts | AI Service | High | Model artifact integrity hash verification (SHA-256) on boot; deterministic fallback engine activates if hash mismatches. |

---

### 2.3 Repudiation (Denial of Action)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-R-01** | Custodian denies authorizing an asset location transfer | API Gateway / Audit Trail | High | Mandatory actor tracking: `transferred_by_id`, timestamp, source location, target location, and approval notes recorded in append-only table. |
| **TH-R-02** | Auditor claims stocktake scan was logged by another user | Audit System | Medium | Stocktake scan log records exact `auditor_id`, session ID, scan timestamp, and device metadata. |

---

### 2.4 Information Disclosure (Data Leakage)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-I-01** | Database backup or connection string leaked in version control | Repository / CI | Critical | Environment variable abstraction (`.env`); automated pre-commit scanning (`git-secrets` / gitleaks); no hardcoded secrets in code. |
| **TH-I-02** | Plaintext password hashes exposed via API response | API Gateway | High | Prisma schema excludes `password` hash from all default queries using sanitized DTO mappers. |
| **TH-I-03** | Detailed stack traces leaked in production error responses | API Gateway | Medium | Global error handler intercepts unhandled exceptions, logs trace to secure log storage, and returns sanitized generic error codes (`HTTP_500`). |

---

### 2.5 Denial of Service (Availability Loss)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-D-01** | High-volume batch inference requests flood AI microservice | AI Service | High | Request queue throttling; request body size limits; lightweight random forest inference (< 5ms execution time). |
| **TH-D-02** | Heavy paginated queries without limit parameters exhaust memory | API Gateway | Medium | Mandatory default pagination (`page=1`, `limit=50`, `maxLimit=100`) enforced across all list endpoints. |

---

### 2.6 Elevation of Privilege (Unauthorized Access)
| Threat ID | Threat Description | Affected Component | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **TH-E-01** | Technician attempts to access `/api/v1/users` or modify system roles | API Gateway | Critical | Role-Based Access Control (`requireRole(['admin'])`) middleware enforced before handler execution. |
| **TH-E-02** | Auditor attempts to close work orders or approve asset disposals | API Gateway | High | Fine-grained permission checks; auditors granted read-only access to work orders and write access strictly to stocktake sessions. |

---

## 3. Residual Risk & Review Cadence
- **Security Audits:** Biannual penetration test and automated dependency vulnerability scanning (`npm audit`, `pip audit`).
- **Review Trigger:** Any modification to authentication primitives or database schema triggers a threat model revision.
