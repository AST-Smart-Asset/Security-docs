# AST Smart Asset Management - RBAC Access Control Matrix

**Project:** Project 3: Smart Asset Inventory & Predictive Maintenance (AST)  
**Institution:** Badr University in Assiut (BUA DevHub Field Phase - Squad 3)  
**Specification:** AST-FR-01 (Role-Based Access Control & User Management)

---

## 1. System Role Definitions

| Role Identifier | Role Name | Primary Responsibilities |
| :--- | :--- | :--- |
| `admin` | System Administrator | User provisioning, role assignments, global system audit inspection, configuration. |
| `facility_manager` | Facility / Operations Manager | Asset registry management, custody transfer approvals, maintenance scheduling, KPI tracking. |
| `technician` | Maintenance Technician | Work order execution, completion logging, component replacement recording, telemetry reading. |
| `auditor` | Compliance & Inventory Auditor | Physical barcode/QR stocktake execution, discrepancy logging, audit reconciliation. |
| `department_head` | Academic / Department Custodian | Custody verification for departmental assets, transfer requests, asset condition viewing. |

---

## 2. Functional Requirements Permission Matrix

Legend:
- **C** = Create / Initiate
- **R** = Read / View
- **U** = Update / Modify
- **D** = Delete / Decommission
- **A** = Approve / Close
- **-** = No Access

| Functional Requirement | admin | facility_manager | technician | auditor | department_head |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **AST-FR-01: Authentication & User Management** | C, R, U, D | R (Self/Dept) | R (Self) | R (Self) | R (Self/Dept) |
| **AST-FR-02: Dashboard & Executive KPIs** | R | R | R (Assigned) | R (Audit metrics) | R (Dept metrics) |
| **AST-FR-03: Asset Registry & Catalog** | C, R, U, D | C, R, U | R | R | R (Dept assets) |
| **AST-FR-04: Digital Custody & Transfer** | R, A | C, R, U, A | R | R | C, R (Dept assets) |
| **AST-FR-05: Depreciation & Valuation** | R, U | R | - | R | R (Dept assets) |
| **AST-FR-06: Maintenance & Work Orders** | R, A | C, R, U, A | R, U (Log labor/parts) | R | C (Report fault), R |
| **AST-FR-07: Stocktake & Physical Audits** | R | C, R, A | R (Read sessions) | C, R, U (Scan tags) | R (Dept results) |
| **AST-FR-08: Reconciliation Discrepancies** | R, A | C, R, U, A | R | C, R, U (Flag missing) | R (Dept assets) |
| **AST-FR-09: Predictive AI Risk Evaluation** | R | R, C (Trigger eval) | R, C (Trigger eval) | R | R |
| **AST-FR-10: Audit Trail & Event Logs** | R (Immutable) | R (Immutable) | R (Self events) | R (Immutable) | R (Dept events) |

---

## 3. Enforcement Implementation

### Backend Middleware:
RBAC permissions are enforced in Node.js/Express route handlers via the `requireRole` and `requirePermission` middlewares:

```typescript
// Example: Restricting Work Order Closure to Technicians & Facility Managers
router.post(
  '/work-orders/:id/close',
  authenticateJwt,
  requireRole(['technician', 'facility_manager', 'admin']),
  closeWorkOrderController
);

// Example: Restricting User Management to System Admin
router.post(
  '/users',
  authenticateJwt,
  requireRole(['admin']),
  createUserController
);
```

### Mobile UI Policy:
- UI action buttons (e.g. "Complete Work Order", "Initiate Transfer", "Start Audit Session") are conditionally mounted based on the authenticated user's active role.
- Server-side validation always acts as the authoritative gatekeeper.
