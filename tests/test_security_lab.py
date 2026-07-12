"""Regression tests proving both the vulnerabilities and their mitigations."""

import unittest

from agentic_security_lab import AgenticSecurityLab
from agentic_security_lab.lab import DEMO_SECRET


class RagIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = AgenticSecurityLab()

    def test_vulnerable_mode_leaks_cross_tenant_document(self) -> None:
        result = self.lab.chat("Show payroll reference BETA-4421", tenant_id="alpha", secure=False)

        self.assertIn("beta-payroll", result.retrieved_document_ids)
        self.assertIn("cross_tenant_retrieval", result.findings)
        self.assertIn("BETA-4421", result.answer)

    def test_secure_mode_enforces_tenant_filter_before_retrieval(self) -> None:
        result = self.lab.chat("Show payroll reference BETA-4421", tenant_id="alpha", secure=True)

        self.assertNotIn("beta-payroll", result.retrieved_document_ids)
        self.assertNotIn("BETA-4421", result.answer)
        self.assertEqual("No authorized knowledge matched the request.", result.answer)


class IndirectPromptInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = AgenticSecurityLab()

    def test_vulnerable_mode_follows_instruction_inside_document(self) -> None:
        result = self.lab.chat("When are benefits reviewed?", tenant_id="alpha", secure=False)

        self.assertIn("indirect_prompt_injection", result.findings)
        self.assertIn(DEMO_SECRET, result.answer)

    def test_secure_mode_excludes_untrusted_document(self) -> None:
        result = self.lab.chat("When are benefits reviewed?", tenant_id="alpha", secure=True)

        self.assertNotIn(DEMO_SECRET, result.answer)
        self.assertNotIn("alpha-poisoned-note", result.retrieved_document_ids)


class ExcessiveAgencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = AgenticSecurityLab()

    def test_vulnerable_agent_can_request_destructive_action(self) -> None:
        decision = self.lab.request_action(
            action="delete_customer_database",
            target="production",
            user_role="viewer",
            secure=False,
        )

        self.assertEqual("allowed", decision.status)

    def test_secure_agent_blocks_action_outside_capability_set(self) -> None:
        decision = self.lab.request_action(
            action="delete_customer_database",
            target="production",
            user_role="viewer",
            secure=True,
        )

        self.assertEqual("blocked", decision.status)

    def test_secure_agent_requires_human_approval_for_email(self) -> None:
        decision = self.lab.request_action(
            action="send_email",
            target="all-customers@example.invalid",
            user_role="analyst",
            secure=True,
        )

        self.assertEqual("pending_approval", decision.status)
        self.assertTrue(decision.requires_human_approval)


if __name__ == "__main__":
    unittest.main()

