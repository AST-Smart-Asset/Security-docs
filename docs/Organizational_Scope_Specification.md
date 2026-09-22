# Organizational Scope Specification

**Specification:** Security & Authorization Hierarchy Specifications  
**Project:** Project 3: Smart Asset Inventory & Predictive Maintenance (AST)  
**Institution:** Badr University in Assiut (BUA DevHub Field Phase - Squad 3)

---

## 1. Purpose

The Organizational Scope model defines which organizational units each user can access. Authorization is based on both the user's role and their assigned organizational scope.

---

## 2. Organization Hierarchy

```
University
└── Campus
    └── Building
        └── College / Department
            └── Floor
                └── Room / Office / Storage Area
```

---

## 3. Role Scope Mapping

| Role | Organizational Scope | Access Rights |
| :--- | :--- | :--- |
| **Asset Administrator** | Assigned Campus / Building / Department | Manage assets within the assigned scope |
| **Procurement / Finance** | Assigned organizational scope | Manage procurement and financial data within the assigned scope |
| **Custodian / Department Manager** | Assigned College / Department | Access and manage assigned departmental assets |
| **Maintenance Technician** | Assigned Building / Campus | Access maintenance-related assets and work orders within the assigned scope |
| **Auditor** | Assigned organizational scope | Read-only access to inventory, financial references, history, and exceptions within the assigned scope |

---

## 4. General Scope Rules

1. **Scope Boundary:** Users can only access resources within their assigned organizational scope.
2. **Inheritance Rule:** Access to a parent organization includes its child organizations.
3. **Isolation Rule:** Users cannot access sibling or unrelated organizations.
4. **Multi-Scope:** A user may possess multiple organizational scope grants.
5. **Backend Enforcement:** Organizational scope is strictly enforced by the backend API and database layer; it cannot be bypassed through the frontend or mobile UI.
6. **Administrative Change Control:** Modifying a user's scope requires appropriate administrative authorization.

---

## 5. `include_descendants` Behaviour

Each scope grant in the `user_scope_grants` table carries an `include_descendants` flag. The behaviour is defined as follows:

- **`include_descendants = TRUE`**:  
  The user can access all child locations in the locations hierarchy under the granted `location_id` without requiring separate explicit grants for each child. The backend resolves the full subtree using recursive CTE queries or hierarchical closure tables.
  
  *Example:* Granting access to `Building A` with `include_descendants = TRUE` automatically grants access to all departments, floors, and rooms within `Building A`.

- **`include_descendants = FALSE`**:  
  The user is restricted strictly and exclusively to that specific node in the hierarchy, with no automatic child traversal.
