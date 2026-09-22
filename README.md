# AST Smart Asset Management - Security & Compliance Documentation

[![Security Specification](https://img.shields.io/badge/Security-AST--SEC--REQ--01..41-red)](https://github.com/AST-Smart-Asset/Security-docs)
[![RBAC](https://img.shields.io/badge/RBAC-5%20Roles%20Enforced-blue)](https://github.com/AST-Smart-Asset/Security-docs)
[![Audit Tests](https://img.shields.io/badge/Audit%20Tests-10%2F10%20Passing-brightgreen)](https://github.com/AST-Smart-Asset/Security-docs)
[![Project 3](https://img.shields.io/badge/BUA-DevHub%20Field%20Phase-navy)](https://github.com/AST-Smart-Asset)

Official Security, Governance, and Access Control Documentation for **Project 3: Smart Asset Inventory & Predictive Maintenance (AST)** at Badr University in Assiut (BUA DevHub Field Phase, Squad 3).

---

## 🛡️ Security Documentation Index

1. **[Authentication and Authorization Model (`docs/Authentication_and_Authorization_Model.md`)](docs/Authentication_and_Authorization_Model.md)**:
   - Security Policy & Governance Specification.
   - Core principle: `User → Role → Permission → Organizational Scope → Resource`.
   - Comprehensive authorization boundaries for the 5 system roles:
     - `Asset Administrator`
     - `Procurement / Finance Viewer`
     - `Custodian / Department Manager`
     - `Maintenance Technician`
     - `Auditor`

2. **[Organizational Scope Specification (`docs/Organizational_Scope_Specification.md`)](docs/Organizational_Scope_Specification.md)**:
   - Multi-tier organizational hierarchy (`University → Campus → Building → College / Department → Floor → Room / Office / Storage Area`).
   - Role-to-Scope mapping rules and cross-organization isolation.
   - Formal specification of `include_descendants = TRUE` behaviour in `user_scope_grants` table for recursive child location resolution.

3. **[RBAC Security Test Specification (`docs/RBAC_Security_Test_Specification.md`)](docs/RBAC_Security_Test_Specification.md)**:
   - Full API access control and security test protocol:
     - `AUTH-01` to `AUTH-05`: Authentication verification.
     - `ADM-01` to `ADM-10`: Asset Administrator lifecycle actions.
     - `PRO-01` to `PRO-09`: Procurement & Finance data access.
     - `CUS-01` to `CUS-10`: Custodian & Department scope isolation.
     - `TECH-01` to `TECH-10`: Maintenance Technician work order boundaries.
     - `AUD-01` to `AUD-09`: Auditor read-only protections.
     - `FIN-01` to `FIN-07`: Financial data isolation tests.
     - `SCOPE-01` to `SCOPE-08`: Organizational scope inheritance & boundary tests.
     - `PRIV-01` to `PRIV-07`: Privilege escalation protection tests.
     - `ADMIN-01` to `ADMIN-07`: Administrative access tests.

4. **[Role-Based Access Control (RBAC) Model (`docs/RBAC_Model_Specification.md`)](docs/RBAC_Model_Specification.md)**:
   - Full 18-resource permission matrix (Asset basic data, locations, custody, conditions, suppliers, purchase orders, invoices, warranties, work orders, retirement, etc.).
   - Permission code definitions (`assets:read`, `assets:write`, `assets:import`, `assets:retire`, `assets:transfer`, `custody:confirm`, `suppliers:write`, `purchase_orders:write`, `invoices:read`, `invoices:write`, `warranties:write`, `financial:read`, `work_orders:read`, `work_orders:update`, `service_events:write`).

5. **[Security Requirements Specification (`docs/Security_Requirements_Specification.md`)](docs/Security_Requirements_Specification.md)**:
   - 41 strict security requirements (`AST-SEC-REQ-01` through `AST-SEC-REQ-41`) covering:
     - Authentication (`AST-SEC-REQ-01..04`)
     - Authorization and RBAC (`AST-SEC-REQ-05..09`)
     - Organizational Scope (`AST-SEC-REQ-10..14`)
     - Asset and Custody Security (`AST-SEC-REQ-15..19`)
     - Financial and Procurement Data (`AST-SEC-REQ-20..23`)
     - File and Attachment Security (`AST-SEC-REQ-24..27`)
     - Audit and Logging (`AST-SEC-REQ-28..31`)
     - API and Application Security (`AST-SEC-REQ-32..36`)
     - AI / Risk Prediction Security (`AST-SEC-REQ-37..40`)
     - Client-Side Token Storage Security (**`AST-SEC-REQ-41`**: mandatory use of `flutter_secure_storage`).
     - Security Acceptance Criteria.

6. **[STRIDE Threat Model (`docs/STRIDE_Threat_Model.md`)](docs/STRIDE_Threat_Model.md)**:
   - Threat matrix analyzing Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege across the 4 trust boundaries.

7. **[Security Hardening Guide (`docs/Security_Hardening_Guide.md`)](docs/Security_Hardening_Guide.md)**:
   - Implementation guidelines for bcrypt work factor 12, JWT 15-minute expiration, Helmet headers, private attachments, and append-only database logs.

---

## 🧪 Automated Security Test Execution

Run the automated test suite directly:

```bash
python tests/security_audit_test.py
```

All 10 test modules validate role boundaries, financial isolation, scope inheritance, and security policies.