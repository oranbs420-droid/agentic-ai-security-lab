# Agentic AI Security Lab

A hands-on portfolio lab for researching, exploiting, measuring, and mitigating security weaknesses in RAG and agentic AI systems.

## Why this project exists

AI applications introduce new trust boundaries between users, retrieved data, language models, tools, APIs, and cloud identities. This project demonstrates those risks through safe, deterministic simulations before introducing real model providers or external integrations.

The repository is designed as evidence for AI Security Researcher, AI Security Engineer, Product Security, AppSec, DevSecOps, and AI Security Architecture roles.

## Phase 1 capabilities

- Vulnerable and secure execution modes
- Cross-tenant RAG leakage demonstration
- Indirect prompt injection through a poisoned document
- Excessive agent agency demonstration
- Deny-by-default tool authorization
- Human approval requirement for sensitive actions
- Audit events for agent decisions
- Automated security regression tests
- Initial OWASP GenAI threat model

## Phase 2 API and vector service

The lab now exposes the research scenarios through a real FastAPI service and
uses ChromaDB as its vector store. A deterministic local embedding keeps the
project free, reproducible, and independent of model-provider credentials.

Start the API:

```bash
python -m pip install ".[dev]"
uvicorn agentic_security_lab.api:app --reload
```

Open `http://127.0.0.1:8000/docs` to use the generated interactive API.

Example secure query:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"query":"payroll reference","tenant_id":"alpha","secure":true}'
```

Set `secure` to `false` only inside this authorized synthetic lab to reproduce
the deliberately vulnerable retrieval and agent behavior.

No external commands, emails, payments, model APIs, or real secrets are used.

## Quick start

```bash
git clone https://github.com/oranbs420-droid/agentic-ai-security-lab.git
cd agentic-ai-security-lab
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install and run the tests:

```bash
python -m pip install .
python -m unittest discover -s tests -v
```

Run the demonstration:

```bash
python demo.py
```

## Research scenarios

| Scenario | Vulnerable mode | Secure mode |
|---|---|---|
| Cross-tenant retrieval | Searches all tenants | Filters by tenant before ranking |
| Indirect prompt injection | Executes an instruction in retrieved text | Excludes content without the required trust state |
| Destructive tool request | Automatically allowed | Blocked by capability policy |
| External email request | Automatically allowed | Requires human approval |

See [the initial threat model](docs/THREAT_MODEL.md) for assets, trust boundaries, abuse cases, and security invariants.

## Planned roadmap

1. **Security core:** deterministic vulnerable/secure comparison and regression tests
2. **RAG service:** FastAPI, ChromaDB, document ingestion, tenant identities, and attack endpoints
3. **Red-team runner:** automated prompt mutations, scoring, evidence capture, and HTML reports
4. **Agent tools:** simulated email, ticket, database, and payment tools with approval policies
5. **Cloud architecture:** Azure Managed Identity, Key Vault, monitoring, CI/CD, and incident response
6. **Research release:** Hebrew/English attack dataset and a documented before/after security evaluation

## Ethical scope

This repository is intended for authorized research and defensive education. Deliberately vulnerable behavior is isolated, deterministic, and uses only synthetic data.
