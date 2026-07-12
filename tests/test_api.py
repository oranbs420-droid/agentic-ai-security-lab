"""HTTP-level security tests for the FastAPI and ChromaDB phase."""

import unittest

from fastapi.testclient import TestClient

from agentic_security_lab.api import create_app
from agentic_security_lab.lab import DEMO_SECRET


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(create_app())

    def test_health_reports_seeded_chromadb_documents(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(200, response.status_code)
        self.assertEqual("ok", response.json()["status"])
        self.assertEqual(3, response.json()["documents"])

    def test_vulnerable_api_retrieves_foreign_tenant_document(self) -> None:
        response = self.client.post(
            "/v1/chat",
            json={
                "query": "Beta payroll internal reference BETA-4421",
                "tenant_id": "alpha",
                "secure": False,
            },
        )

        body = response.json()
        self.assertEqual(200, response.status_code)
        self.assertIn("beta-payroll", body["retrieved_document_ids"])
        self.assertIn("cross_tenant_retrieval", body["findings"])

    def test_secure_api_filters_foreign_tenant_inside_vector_query(self) -> None:
        response = self.client.post(
            "/v1/chat",
            json={
                "query": "Beta payroll internal reference BETA-4421",
                "tenant_id": "alpha",
                "secure": True,
            },
        )

        body = response.json()
        self.assertEqual(200, response.status_code)
        self.assertNotIn("beta-payroll", body["retrieved_document_ids"])
        self.assertNotIn("cross_tenant_retrieval", body["findings"])

    def test_vulnerable_api_executes_indirect_injection(self) -> None:
        response = self.client.post(
            "/v1/chat",
            json={
                "query": "Benefits reviewed January",
                "tenant_id": "alpha",
                "secure": False,
            },
        )

        body = response.json()
        self.assertIn("indirect_prompt_injection", body["findings"])
        self.assertIn(DEMO_SECRET, body["answer"])

    def test_secure_api_requires_approval_for_sensitive_tool(self) -> None:
        response = self.client.post(
            "/v1/actions/evaluate",
            json={
                "action": "send_email",
                "target": "all-customers@example.invalid",
                "user_role": "analyst",
                "secure": True,
            },
        )

        body = response.json()
        self.assertEqual("pending_approval", body["status"])
        self.assertTrue(body["requires_human_approval"])

    def test_api_rejects_invalid_tenant_identifier(self) -> None:
        response = self.client.post(
            "/v1/chat",
            json={
                "query": "payroll",
                "tenant_id": "../../beta",
                "secure": True,
            },
        )

        self.assertEqual(422, response.status_code)


if __name__ == "__main__":
    unittest.main()

