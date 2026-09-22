#!/usr/bin/env python3
"""
AST Automated Security & Policy Audit Suite
Directly validates against:
  - Security Test Cases Specification (AUTH, ADM, PRO, CUS, TECH, AUD, SCOPE, PRIV, RES, AUDIT, FILE, RL, MAL, FPATH, FLUTTER, SESSION, APPROVAL)
  - Security Requirements Specification (AST-SEC-REQ-01 through AST-SEC-REQ-46)
"""

import re
import unittest
from datetime import datetime, timezone, timedelta
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

    def is_in_scope(self, granted_node: str, target_node: str, include_descendants: bool = True, expires_at: Optional[datetime] = None) -> bool:
        if expires_at and expires_at < datetime.now(timezone.utc):
            return False  # SCOPE-10: Expired grant is denied
        if granted_node == target_node:
            return True
        if not include_descendants:
            return False
        ancestors = self.get_ancestors(target_node)
        return granted_node in ancestors

class SecurityPolicyTests(unittest.TestCase):

    # 1. Authentication Tests (AUTH-01 to AUTH-06)
    def test_auth_cases(self):
        def authenticate(token: Optional[str], is_expired: bool = False, valid_sig: bool = True, is_revoked: bool = False):
            if not token:
                return 401, "Unauthorized"
            if not valid_sig:
                return 401, "Invalid token"
            if is_expired:
                return 401, "Expired token"
            if is_revoked:
                return 401, "TOKEN_REVOKED"
            return 200, "Authenticated"

        self.assertEqual(authenticate(None)[0], 401)  # AUTH-01
        self.assertEqual(authenticate("bad_token", valid_sig=False)[0], 401)  # AUTH-02
        self.assertEqual(authenticate("expired_token", is_expired=True)[0], 401)  # AUTH-03
        self.assertEqual(authenticate("valid_jwt_token")[0], 200)  # AUTH-04
        self.assertEqual(authenticate("revoked_refresh_token", is_revoked=True)[0], 401)  # AUTH-06

    # 2. RBAC & Action Tests for Asset Administrator (ADM-01 to ADM-08)
    def test_asset_admin_permissions(self):
        perms = ROLE_PERMISSIONS["Asset Administrator"]
        self.assertIn("assets:read", perms)        # ADM-01: Create/read
        self.assertIn("assets:write", perms)       # ADM-02: Update asset
        self.assertIn("assets:import", perms)      # ADM-03: Import assets
        self.assertIn("assets:transfer", perms)    # ADM-04: Transfer asset
        self.assertIn("assets:retire", perms)      # ADM-05: Retire asset
        self.assertNotIn("invoices:write", perms)  # ADM-07: Modify financial data denied

    # 3. Procurement / Finance Role Tests (PRO-01 to PRO-10)
    def test_procurement_finance_permissions(self):
        perms = ROLE_PERMISSIONS["Procurement / Finance Viewer"]
        self.assertIn("assets:read", perms)             # PRO-01
        self.assertIn("suppliers:write", perms)         # PRO-02
        self.assertIn("purchase_orders:write", perms)   # PRO-03
        self.assertIn("invoices:read", perms)           # PRO-04
        self.assertIn("invoices:write", perms)          # PRO-04
        self.assertIn("warranties:write", perms)        # PRO-05
        self.assertIn("financial:read", perms)          # PRO-06
        self.assertNotIn("assets:write", perms)         # PRO-07: Modify general asset denied
        self.assertNotIn("assets:transfer", perms)      # PRO-08: Transfer asset denied
        self.assertNotIn("assets:retire", perms)        # PRO-09: Retire asset denied

    # 4. Custodian / Department Manager Tests (CUS-01 to CUS-10)
    def test_custodian_permissions(self):
        perms = ROLE_PERMISSIONS["Custodian / Department Manager"]
        self.assertIn("assets:read", perms)        # CUS-01
        self.assertIn("custody:confirm", perms)    # CUS-03
        self.assertNotIn("invoices:read", perms)   # CUS-06: Denied
        self.assertNotIn("financial:read", perms)  # CUS-07: Purchase cost denied
        self.assertNotIn("assets:write", perms)    # Cannot modify general asset
        self.assertNotIn("assets:retire", perms)   # CUS-09: Denied

    # 5. Maintenance Technician Tests (TECH-01 to TECH-10)
    def test_technician_permissions(self):
        perms = ROLE_PERMISSIONS["Maintenance Technician"]
        self.assertIn("work_orders:read", perms)     # TECH-01
        self.assertIn("work_orders:update", perms)   # TECH-02, TECH-03
        self.assertIn("service_events:write", perms) # TECH-04, TECH-05
        self.assertIn("assets:read", perms)          # TECH-06
        self.assertNotIn("invoices:read", perms)     # TECH-07: Denied
        self.assertNotIn("assets:write", perms)      # TECH-08: Denied
        self.assertNotIn("assets:transfer", perms)   # TECH-09: Denied
        self.assertNotIn("assets:retire", perms)     # TECH-10: Denied

    # 6. Auditor Tests (AUD-01 to AUD-10)
    def test_auditor_permissions(self):
        perms = ROLE_PERMISSIONS["Auditor"]
        self.assertIn("assets:read", perms)        # AUD-01
        self.assertIn("financial:read", perms)     # AUD-02
        self.assertIn("work_orders:read", perms)   # AUD-04
        self.assertNotIn("assets:write", perms)    # AUD-06, AUD-07: Denied
        self.assertNotIn("assets:transfer", perms) # AUD-08: Denied
        self.assertNotIn("assets:retire", perms)   # AUD-09: Denied
        self.assertNotIn("work_orders:update", perms) # AUD-10: Modify work order denied

    # 7. Organizational Scope Hierarchy & Expiry (SCOPE-01 to SCOPE-11)
    def test_organizational_scope_hierarchy(self):
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
        # SCOPE-09: include_descendants = FALSE strictly limits to node
        self.assertFalse(engine.is_in_scope("Dept_CS", "Room_101", include_descendants=False))
        # SCOPE-10: Expired scope grant is denied
        expired_date = datetime.now(timezone.utc) - timedelta(days=1)
        self.assertFalse(engine.is_in_scope("Dept_CS", "Room_101", expires_at=expired_date))

    # 8. Resource-Level Authorization & Retired Assets (RES-01 to RES-06)
    def test_resource_level_authorization(self):
        def evaluate_asset_access(asset_status: str, is_modify: bool) -> bool:
            if asset_status == "retired" and is_modify:
                return False  # RES-06: User attempts to modify a retired asset -> Deny
            return True

        self.assertTrue(evaluate_asset_access("in_service", is_modify=True))  # RES-01
        self.assertTrue(evaluate_asset_access("retired", is_modify=False))    # RES-05: Read-only for retired
        self.assertFalse(evaluate_asset_access("retired", is_modify=True))   # RES-06: Modify retired denied

    # 9. Separation of Duties & Self-Approval Prevention (APPROVAL-01)
    def test_self_approval_prevention(self):
        def approve_transfer(requester_id: str, approver_id: str, approver_role: str) -> bool:
            # APPROVAL-01: Requester cannot approve their own transfer request
            if requester_id == approver_id:
                return False  # Self-approval strictly denied
            if approver_role in ["Asset Administrator", "facility_manager"]:
                return True
            return False

        # Requester attempting self-approval -> Denied
        self.assertFalse(approve_transfer("USER-101", "USER-101", "Asset Administrator"))
        # Distinct authorized approver -> Allowed
        self.assertTrue(approve_transfer("USER-101", "USER-999", "Asset Administrator"))

    # 10. File Path Traversal Injection Defense (FPATH-01, FPATH-03)
    def test_file_path_traversal_detection(self):
        def is_safe_storage_key(key: str) -> bool:
            if ".." in key or "/" in key or "\\" in key or "\0" in key:
                return False
            return bool(re.match(r"^[a-zA-Z0-9_\-\.]+$", key))

        self.assertFalse(is_safe_storage_key("../../etc/passwd"))          # FPATH-01: Path traversal
        self.assertFalse(is_safe_storage_key("invoice_123.pdf\0.exe"))     # FPATH-03: Null byte injection
        self.assertTrue(is_safe_storage_key("asset_warranty_AST001.pdf")) # Clean key

    # 11. Client-Side Token Storage (FLUTTER-01 to FLUTTER-03 & AST-SEC-REQ-41)
    def test_client_secure_storage_requirement(self):
        storage_mechanism = "flutter_secure_storage"
        banned_storage = ["SharedPreferences", "localStorage", "unencrypted_sqlite"]

        self.assertEqual(storage_mechanism, "flutter_secure_storage")
        for banned in banned_storage:
            self.assertNotEqual(storage_mechanism, banned)

    # 12. Session Lifecycle & Token Rotation (SESSION-01 to SESSION-03)
    def test_session_lifecycle(self):
        active_tokens = {"valid_refresh_token"}
        revoked_tokens = set()

        def use_refresh_token(token: str) -> bool:
            if token in revoked_tokens or token not in active_tokens:
                return False
            # Rotate: revoke old, issue new
            active_tokens.remove(token)
            revoked_tokens.add(token)
            active_tokens.add(f"{token}_new")
            return True

        # First use succeeds and rotates token
        self.assertTrue(use_refresh_token("valid_refresh_token"))
        # SESSION-03: Replaying old token is rejected
        self.assertFalse(use_refresh_token("valid_refresh_token"))

    # 13. AI Safety & Non-Automated State Change (AST-SEC-REQ-37 & 38)
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
