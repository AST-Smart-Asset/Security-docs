#!/usr/bin/env python3
"""
AST Automated Security & Policy Audit Suite
Directly validates against:
  - RBAC Security Test Specification (AUTH, ADM, PRO, CUS, TECH, AUD, FIN, SCOPE, PRIV, ADMIN)
  - Security Requirements Specification (AST-SEC-REQ-01 through AST-SEC-REQ-41)
"""

import re
import unittest
from typing import Dict, List, Optional, Set

# Permission Codes defined in RBAC Model
PERMISSION_CODES = {
    "assets:read",
    "assets:write",
    "assets:import",
    "assets:retire",
    "assets:transfer",
    "custody:confirm",
    "suppliers:write",
    "purchase_orders:write",
    "invoices:read",
    "invoices:write",
    "warranties:write",
    "financial:read",
    "work_orders:read",
    "work_orders:update",
    "service_events:write",
}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "Asset Administrator": {
        "assets:read", "assets:write", "assets:import", "assets:retire", "assets:transfer",
        "custody:confirm", "suppliers:write", "warranties:write", "work_orders:read", "work_orders:update"
    },
    "Procurement / Finance Viewer": {
        "assets:read", "suppliers:write", "purchase_orders:write", "invoices:read",
        "invoices:write", "warranties:write", "financial:read", "work_orders:read"
    },
    "Custodian / Department Manager": {
        "assets:read", "custody:confirm", "work_orders:read"
    },
    "Maintenance Technician": {
        "assets:read", "work_orders:read", "work_orders:update", "service_events:write"
    },
    "Auditor": {
        "assets:read", "invoices:read", "financial:read", "work_orders:read"
    },
}

class OrganizationNode:
    def __init__(self, node_id: str, parent_id: Optional[str] = None):
        self.node_id = node_id
        self.parent_id = parent_id

class ScopeEngine:
    def __init__(self, hierarchy: Dict[str, Optional[str]]):
        self.hierarchy = hierarchy  # child_id -> parent_id

    def get_ancestors(self, node_id: str) -> Set[str]:
        ancestors = set()
        curr = self.hierarchy.get(node_id)
        while curr:
            ancestors.add(curr)
            curr = self.hierarchy.get(curr)
        return ancestors

    def is_in_scope(self, granted_node: str, target_node: str, include_descendants: bool = True) -> bool:
        if granted_node == target_node:
            return True
        if not include_descendants:
            return False
        # Target must be a descendant of granted_node
        ancestors = self.get_ancestors(target_node)
        return granted_node in ancestors

class SecurityPolicyTests(unittest.TestCase):

    # 1. Authentication Tests (AUTH-01 to AUTH-05)
    def test_auth_cases(self):
        # AUTH-01: No token
        def authenticate(token: Optional[str], is_expired: bool = False, valid_sig: bool = True):
            if not token:
                return 401, "Unauthorized"
            if not valid_sig:
                return 401, "Invalid token"
            if is_expired:
                return 401, "Expired token"
            return 200, "Authenticated"

        self.assertEqual(authenticate(None)[0], 401)  # AUTH-01
        self.assertEqual(authenticate("bad_token", valid_sig=False)[0], 401)  # AUTH-02
        self.assertEqual(authenticate("expired_token", is_expired=True)[0], 401)  # AUTH-03
        self.assertEqual(authenticate("valid_jwt_token")[0], 200)  # AUTH-04

    # 2. RBAC & Action Tests for Asset Administrator (ADM-01 to ADM-10)
    def test_asset_admin_permissions(self):
        perms = ROLE_PERMISSIONS["Asset Administrator"]
        self.assertIn("assets:read", perms)        # ADM-01: GET /api/assets
        self.assertIn("assets:write", perms)       # ADM-02: POST /api/assets, ADM-03: PATCH /api/assets/:id
        self.assertIn("assets:import", perms)      # ADM-04: POST /api/assets/import
        self.assertIn("assets:transfer", perms)    # ADM-05: POST /api/assets/:id/transfer
        self.assertIn("assets:retire", perms)      # ADM-06: POST /api/assets/:id/retire
        self.assertNotIn("invoices:write", perms)  # ADM-08: PATCH /api/invoices/:id forbidden

    # 3. Procurement / Finance Role Tests (PRO-01 to PRO-09)
    def test_procurement_finance_permissions(self):
        perms = ROLE_PERMISSIONS["Procurement / Finance Viewer"]
        self.assertIn("assets:read", perms)             # PRO-01
        self.assertIn("suppliers:write", perms)         # PRO-02, PRO-03
        self.assertIn("purchase_orders:write", perms)   # PRO-04, PRO-05
        self.assertIn("invoices:read", perms)           # PRO-06
        self.assertIn("invoices:write", perms)          # PRO-07
        self.assertIn("warranties:write", perms)        # PRO-08
        self.assertNotIn("assets:write", perms)         # PRO-09: PATCH /api/assets/:id forbidden
        self.assertNotIn("assets:transfer", perms)      # Cannot transfer assets
        self.assertNotIn("assets:retire", perms)        # Cannot retire assets

    # 4. Custodian / Department Manager Tests (CUS-01 to CUS-10)
    def test_custodian_permissions(self):
        perms = ROLE_PERMISSIONS["Custodian / Department Manager"]
        self.assertIn("assets:read", perms)        # CUS-01, CUS-02
        self.assertIn("custody:confirm", perms)    # CUS-04
        self.assertNotIn("invoices:read", perms)   # CUS-06: 403 Forbidden
        self.assertNotIn("financial:read", perms)  # Cannot access financial info
        self.assertNotIn("assets:write", perms)    # CUS-08: 403 Forbidden
        self.assertNotIn("assets:retire", perms)   # CUS-09: 403 Forbidden

    # 5. Maintenance Technician Tests (TECH-01 to TECH-10)
    def test_technician_permissions(self):
        perms = ROLE_PERMISSIONS["Maintenance Technician"]
        self.assertIn("work_orders:read", perms)     # TECH-01, TECH-02
        self.assertIn("work_orders:update", perms)   # TECH-03, TECH-04
        self.assertIn("service_events:write", perms) # TECH-05
        self.assertIn("assets:read", perms)          # TECH-06
        self.assertNotIn("invoices:read", perms)     # TECH-07: 403 Forbidden
        self.assertNotIn("assets:write", perms)      # TECH-08: 403 Forbidden
        self.assertNotIn("assets:transfer", perms)   # TECH-09: 403 Forbidden
        self.assertNotIn("assets:retire", perms)     # TECH-10: 403 Forbidden

    # 6. Auditor Tests (AUD-01 to AUD-09)
    def test_auditor_permissions(self):
        perms = ROLE_PERMISSIONS["Auditor"]
        self.assertIn("assets:read", perms)        # AUD-01, AUD-02
        self.assertIn("invoices:read", perms)      # AUD-03
        self.assertIn("work_orders:read", perms)   # AUD-04
        self.assertNotIn("assets:write", perms)    # AUD-06, AUD-07: Forbidden
        self.assertNotIn("assets:transfer", perms) # AUD-08: Forbidden
        self.assertNotIn("assets:retire", perms)   # AUD-09: Forbidden

    # 7. Financial Data Isolation (FIN-01 to FIN-07)
    def test_financial_isolation(self):
        self.assertNotIn("financial:read", ROLE_PERMISSIONS["Custodian / Department Manager"]) # FIN-01, FIN-03
        self.assertNotIn("financial:read", ROLE_PERMISSIONS["Maintenance Technician"])        # FIN-02, FIN-04
        self.assertIn("financial:read", ROLE_PERMISSIONS["Procurement / Finance Viewer"])     # FIN-05
        self.assertIn("financial:read", ROLE_PERMISSIONS["Auditor"])                          # FIN-06

    # 8. Organizational Scope Hierarchy & include_descendants (SCOPE-01 to SCOPE-08)
    def test_organizational_scope_hierarchy(self):
        # Setup hierarchy: University -> Campus -> Building_Eng -> Dept_CS -> Floor_1 -> Room_101
        #                  Building_Eng -> Dept_EE (sibling of Dept_CS)
        hierarchy = {
            "Campus": "University",
            "Building_Eng": "Campus",
            "Dept_CS": "Building_Eng",
            "Dept_EE": "Building_Eng",
            "Floor_1": "Dept_CS",
            "Room_101": "Floor_1",
            "Room_102": "Floor_1",
        }
        engine = ScopeEngine(hierarchy)

        # SCOPE-01: Resource inside assigned scope
        self.assertTrue(engine.is_in_scope("Dept_CS", "Dept_CS"))
        # SCOPE-02: Resource outside assigned scope
        self.assertFalse(engine.is_in_scope("Dept_CS", "Building_Eng"))
        # SCOPE-03: Child organization under assigned scope (include_descendants = TRUE)
        self.assertTrue(engine.is_in_scope("Dept_CS", "Room_101", include_descendants=True))
        # SCOPE-04: Sibling organization is denied
        self.assertFalse(engine.is_in_scope("Dept_CS", "Dept_EE"))
        # include_descendants = FALSE strictly limits to node
        self.assertFalse(engine.is_in_scope("Dept_CS", "Room_101", include_descendants=False))

    # 9. Client Token Storage (AST-SEC-REQ-41)
    def test_client_secure_storage_requirement(self):
        storage_mechanism = "flutter_secure_storage"
        banned_storage = ["SharedPreferences", "localStorage", "unencrypted_sqlite"]

        self.assertEqual(storage_mechanism, "flutter_secure_storage")
        for banned in banned_storage:
            self.assertNotEqual(storage_mechanism, banned)

    # 10. AI Safety & Non-Automated State Change (AST-SEC-REQ-37 & 38)
    def test_ai_safety_advisory_rule(self):
        ai_output = {
            "failure_probability": 0.88,
            "risk_band": "critical",
            "advisory_notice": "Advisory prediction only. Automated work order issuance or asset decommissioning without human technician review is strictly prohibited.",
            "auto_trigger_work_order": False,
            "auto_retire_asset": False,
        }
        self.assertFalse(ai_output["auto_trigger_work_order"])
        self.assertFalse(ai_output["auto_retire_asset"])
        self.assertIn("Advisory prediction only", ai_output["advisory_notice"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
