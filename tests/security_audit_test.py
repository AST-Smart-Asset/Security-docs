#!/usr/bin/env python3
"""
AST Automated Security & Policy Audit Suite
Tests password policies, RBAC matrices, token authorization, and sanitization.
"""

import re
import unittest

class SecurityPolicyTests(unittest.TestCase):

    # 1. Password Complexity Verification
    def validate_password_strength(self, password: str) -> bool:
        """Enforces minimum 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char."""
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def test_password_policy_enforcement(self):
        self.assertTrue(self.validate_password_strength("Password123!"))
        self.assertTrue(self.validate_password_strength("SecureAdmin@2026"))
        self.assertFalse(self.validate_password_strength("weak"))
        self.assertFalse(self.validate_password_strength("alllowercase123!"))
        self.assertFalse(self.validate_password_strength("ALLUPPERCASE123!"))
        self.assertFalse(self.validate_password_strength("NoSpecialChar123"))

    # 2. RBAC Permission Engine Verification
    def check_rbac_permission(self, role: str, action: str) -> bool:
        rbac_rules = {
            "admin": ["users:manage", "assets:create", "assets:delete", "work_orders:close", "stocktake:audit"],
            "facility_manager": ["assets:create", "assets:update", "work_orders:close", "custody:approve"],
            "technician": ["work_orders:close", "work_orders:update", "predictions:evaluate"],
            "auditor": ["stocktake:audit", "stocktake:scan", "discrepancies:flag"],
            "department_head": ["custody:request", "assets:view_dept"],
        }
        allowed_actions = rbac_rules.get(role, [])
        return action in allowed_actions

    def test_rbac_boundary_enforcement(self):
        # Technicians cannot delete assets or manage users
        self.assertFalse(self.check_rbac_permission("technician", "assets:delete"))
        self.assertFalse(self.check_rbac_permission("technician", "users:manage"))
        self.assertTrue(self.check_rbac_permission("technician", "work_orders:close"))

        # Auditors can scan stocktake but cannot close work orders
        self.assertTrue(self.check_rbac_permission("auditor", "stocktake:audit"))
        self.assertFalse(self.check_rbac_permission("auditor", "work_orders:close"))

        # Admins have master provisioning rights
        self.assertTrue(self.check_rbac_permission("admin", "users:manage"))
        self.assertTrue(self.check_rbac_permission("admin", "assets:delete"))

    # 3. Input Sanitization & Injection Defense
    def detect_malicious_input(self, input_str: str) -> bool:
        """Returns True if SQL injection or XSS pattern is detected."""
        sql_patterns = [
            r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)",
            r"(--|\#|\/\*|\*\/)",
            r"(\bOR\b\s+['\"0-9]+=['\"0-9]+)",
        ]
        xss_patterns = [
            r"(<script.*?>|<\/script>)",
            r"(javascript:)",
            r"(onload=|onerror=)",
        ]
        combined = "|".join(sql_patterns + xss_patterns)
        return bool(re.search(combined, input_str, re.IGNORECASE))

    def test_input_injection_detection(self):
        self.assertTrue(self.detect_malicious_input("AST-101' OR '1'='1"))
        self.assertTrue(self.detect_malicious_input("<script>alert('pwned')</script>"))
        self.assertTrue(self.detect_malicious_input("DROP TABLE assets; --"))
        self.assertFalse(self.detect_malicious_input("AST-HVAC-001"))
        self.assertFalse(self.detect_malicious_input("Routine maintenance performed on chiller."))

if __name__ == "__main__":
    unittest.main(verbosity=2)
