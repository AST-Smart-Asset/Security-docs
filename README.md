# AST Smart Asset Management - Security & Compliance Documentation

[![Security Standard](https://img.shields.io/badge/STRIDE-Threat%20Model-red)](https://github.com/AST-Smart-Asset/Security-docs)
[![RBAC](https://img.shields.io/badge/RBAC-Enforced-blue)](https://github.com/AST-Smart-Asset/Security-docs)
[![Audit Tests](https://img.shields.io/badge/Audit%20Tests-Passing-brightgreen)](https://github.com/AST-Smart-Asset/Security-docs)
[![Project 3](https://img.shields.io/badge/BUA-DevHub%20Field%20Phase-navy)](https://github.com/AST-Smart-Asset)

Security architecture, STRIDE threat models, RBAC access control matrices, and hardening guidelines for **Project 3: Smart Asset Inventory & Predictive Maintenance (AST)** at Badr University in Assiut (BUA DevHub Field Phase, Squad 3).

---

## 🛡️ Documentation Catalog

1. **[STRIDE Threat Model (`docs/STRIDE_Threat_Model.md`)](docs/STRIDE_Threat_Model.md):**
   - Full component-level analysis across all 6 STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
   - Trust boundaries: Mobile Client $\to$ API Gateway $\to$ PostgreSQL Database $\to$ AI Microservice $\to$ Physical Asset Tags.
   - Comprehensive risk treatment and mitigation catalog.

2. **[RBAC Access Matrix (`docs/RBAC_Access_Matrix.md`)](docs/RBAC_Access_Matrix.md):**
   - Fine-grained role definitions for `admin`, `facility_manager`, `technician`, `auditor`, and `department_head`.
   - Granular CRUD and Approval permissions mapped to Functional Requirements (AST-FR-01 through AST-FR-10).
   - Middleware implementation patterns for Express and Flutter UI guard checks.

3. **[Security Hardening Guide (`docs/Security_Hardening_Guide.md`)](docs/Security_Hardening_Guide.md):**
   - Cryptographic standards: bcrypt work factor $\ge 12$, short-lived JWTs (15m), and secure token storage (Android Keystore / iOS Keychain).
   - Append-only event log immutability (`asset_events` table).
   - Container and Docker hardening guidelines (non-root users, minimal attack surface).

4. **[Automated Security Test Suite (`tests/security_audit_test.py`)](tests/security_audit_test.py):**
   - Unit tests validating password strength policies, RBAC access gates, and input injection detection (SQLi / XSS).

---

## 🧪 Running Security Audit Tests

```bash
python tests/security_audit_test.py
```
Outputs validation checks confirming that unauthorized operations are blocked and password/sanitization policies are enforced.