import pytest
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────────────────────
# CONCEPT: Why mock?
# Your auditor talks to GCP APIs. In CI/CD there's no real GCP
# project. So we "mock" — fake the API responses — to test logic
# without a real cloud connection. The test checks YOUR code,
# not Google's infrastructure.
# ─────────────────────────────────────────────────────────────


class TestIAMBasicRisks:
    """Tests for high-severity IAM misconfigurations"""

    def test_detects_primitive_role_on_user(self):
        """
        GIVEN: A user account has roles/owner
        WHEN:  We analyze the IAM policy
        THEN:  The auditor flags it as HIGH risk
        
        Primitive roles (owner/editor/viewer) are considered bad practice
        because they grant too many permissions at once.
        """
        # Arrange: build a fake IAM policy binding
        fake_binding = {
            "role": "roles/owner",
            "members": ["user:admin@example.com"]
        }
        fake_policy = {"bindings": [fake_binding]}

        # This is where your auditor function goes
        # from scanner.iam_auditor import analyze_policy
        # result = analyze_policy(fake_policy)
        # assert result[0]["severity"] == "HIGH"
        
        # For now: placeholder so the test file is valid
        assert fake_binding["role"] == "roles/owner"

    def test_detects_allUsers_binding(self):
        """
        GIVEN: A resource has allUsers or allAuthenticatedUsers as a member
        WHEN:  We analyze the policy
        THEN:  The auditor flags it as CRITICAL — public exposure
        
        allUsers = literally anyone on the internet. Always a red flag.
        """
        fake_binding = {
            "role": "roles/storage.objectViewer",
            "members": ["allUsers"]
        }
        fake_policy = {"bindings": [fake_binding]}

        # TODO (YOUR JOB):
        # 1. Import your analyze_policy function (once you write it)
        # 2. Call it with fake_policy
        # 3. Assert the result severity == "CRITICAL"
        # 4. Assert the result contains the member "allUsers"
        
        assert "allUsers" in fake_binding["members"]  # placeholder

    def test_detects_service_account_with_owner_role(self):
        """
        GIVEN: A service account has roles/editor
        WHEN:  We analyze the policy
        THEN:  The auditor flags it — service accounts shouldn't have primitive roles
        """
        fake_binding = {
            "role": "roles/editor",
            "members": ["serviceAccount:my-sa@project.iam.gserviceaccount.com"]
        }
        fake_policy = {"bindings": [fake_binding]}

        assert "serviceAccount" in fake_binding["members"][0]  # placeholder


# ─────────────────────────────────────────────────────────────
# YOUR 50%: Write these 3 tests below
# Follow the exact same pattern above.
# Each test must have: Arrange → Act → Assert
# ─────────────────────────────────────────────────────────────

class TestIAMEdgeCases:
    """Your job: write these tests"""

    def test_empty_policy_returns_no_findings(self):
        """
        GIVEN: An IAM policy with no bindings (empty project)
        WHEN:  We analyze it
        THEN:  We get back an empty findings list, no crash
        
        WHY THIS MATTERS: Auditors must handle empty/clean environments
        gracefully. A crash on empty input = bad tool.
        """
        # TODO: Write this test
        # Hint: fake_policy = {"bindings": []}
        pass

    def test_multiple_bindings_flags_all_violations(self):
        """
        GIVEN: A policy with 3 bindings, 2 of which are violations
        WHEN:  We analyze it
        THEN:  We get exactly 2 findings back
        
        WHY THIS MATTERS: Real GCP projects have dozens of bindings.
        Your tool must catch ALL of them, not just the first one.
        """
        # TODO: Write this test
        # Hint: build fake_policy with 3 bindings:
        #   - one safe (roles/storage.objectViewer on a user)
        #   - one violation (roles/owner on a user)
        #   - one violation (allUsers on any role)
        pass

    def test_legitimate_role_returns_no_finding(self):
        """
        GIVEN: A user has roles/storage.objectViewer (a specific, scoped role)
        WHEN:  We analyze the policy
        THEN:  No findings — this is a legitimate, least-privilege binding
        
        WHY THIS MATTERS: False positives destroy trust in security tools.
        A good auditor knows what is safe, not just what's dangerous.
        """
        # TODO: Write this test
        pass
