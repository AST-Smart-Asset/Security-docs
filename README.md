# AST Smart Asset Management - Security & Compliance Documentation

[![Security Specification](https://img.shields.io/badge/Security-AST--SEC--REQ--01..46-red)](https://github.com/AST-Smart-Asset/Security-docs)
[![RBAC](https://img.shields.io/badge/RBAC-5%20Roles%20Enforced-blue)](https://github.com/AST-Smart-Asset/Security-docs)
[![Audit Tests](https://img.shields.io/badge/Audit%20Tests-13%2F13%20Passing-brightgreen)](https://github.com/AST-Smart-Asset/Security-docs)
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

3. **[Security Test Cases Specification (`docs/Security_Test_Cases_Specification.md`)](docs/Security_Test_Cases_Specification.md)**:
   - Complete 20-suite test specification covering:
     - `AUTH-01` to `AUTH-06`: Authentication & token revocation tests.
     - `ADM-01` to `ADM-08`: Asset Administrator lifecycle tests.
     - `PRO-01` to `PRO-10`: Procurement & Finance boundary tests.
     - `CUS-01` to `CUS-10`: Custodian & Department scope isolation tests.
     - `TECH-01` to `TECH-10`: Maintenance Technician work order tests.
     - `AUD-01` to `AUD-10`: Auditor read-only tests.
     - `SCOPE-01` to `SCOPE-08`: Organizational scope inheritance tests.
     - `PRIV-01` to `PRIV-07`: Privilege escalation prevention tests.
     - `RES-01` to `RES-06`: Resource-level authorization tests.
     - `AUDIT-01` to `AUDIT-06`: Audit logging verification tests.
     - `FILE-01` to `FILE-05`: File & attachment access tests.
     - `RL-01` to `RL-04`: Rate limiting & brute force lockout tests.
     - `MAL-01` to `MAL-05`: Malware scanning & quarantine tests.
     - `FPATH-01` to `FPATH-04`: Path traversal & storage key injection tests.
     - `FLUTTER-01` to `FLUTTER-08`: Flutter client-side token storage tests (`flutter_secure_storage`).
     - `SCOPE-09` to `SCOPE-11`: Grant expiry & `include_descendants` tests.
     - `SESSION-01` to `SESSION-03`: Session lifecycle & token rotation tests.
     - `APPROVAL-01`: Self-approval prevention tests.

4. **[Role-Based Access Control (RBAC) Model (`docs/RBAC_Model_Specification.md`)](docs/RBAC_Model_Specification.md)**:
   - Full 18-resource permission matrix (Asset basic data, locations, custody, conditions, suppliers, purchase orders, invoices, warranties, work orders, retirement, etc.).
   - Permission code definitions (`assets:read`, `assets:write`, `assets:import`, `assets:retire`, `assets:transfer`, `custody:confirm`, `suppliers:write`, `purchase_orders:write`, `invoices:read`, `invoices:write`, `warranties:write`, `financial:read`, `work_orders:read`, `work_orders:update`, `service_events:write`).

5. **[Security Requirements Specification (`docs/Security_Requirements_Specification.md`)](docs/Security_Requirements_Specification.md)**:
   - Strict security requirements (`AST-SEC-REQ-01` through `AST-SEC-REQ-46`) covering:
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

6. **[Threat Model: Revised Specification (`docs/Threat_Model_Revised.md`)](docs/Threat_Model_Revised.md)**:
   - 12-row Threat Register linking threats to risks, controls, and mapped requirements (01-53).
   - 5 Primary Attack Paths (Cross-tenant IDOR, Self-approval, Path traversal, Injection, AI autonomous failure).
   - Risk treatment, verification criteria, and residual risk ownership.

7. **[Security Hardening Guide (`docs/Security_Hardening_Guide.md`)](docs/Security_Hardening_Guide.md)**:
   - Implementation guidelines for bcrypt work factor 12, JWT 15-minute expiration, Helmet headers, private attachments, and append-only database logs.

---

## 🧪 Automated Security Test Execution

Run the automated test suite directly:

```bash
python tests/security_audit_test.py
```

All 13 test suites validate role boundaries, financial isolation, scope inheritance, self-approval prevention, file traversal defense, token rotation, and hardware keystore encryption.