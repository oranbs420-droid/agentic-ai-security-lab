# Threat Model: Agentic AI Security Lab

## System purpose

The lab compares intentionally vulnerable and secured implementations of a multi-tenant RAG assistant with simulated tools. It contains no real credentials and performs no external actions.

## Assets

- Tenant-private documents and embeddings
- Agent instructions and configuration
- Tool authorization policy
- Audit evidence
- Cost and availability of AI services

## Trust boundaries

1. User input entering the application
2. Documents entering the retrieval pipeline
3. Retrieved content entering the model context
4. Model output reaching the tool dispatcher
5. Tenant identity reaching the vector search layer

## Initial abuse cases

| ID | Abuse case | OWASP GenAI category | Vulnerable behavior | Secure control |
|---|---|---|---|---|
| TM-01 | Instruction hidden inside a retrieved document | LLM01 Prompt Injection | Retrieved text is treated as authority | Trust labels and exclusion of untrusted content |
| TM-02 | User retrieves another tenant's document | LLM08 Vector and Embedding Weaknesses | Authorization filter is omitted | Tenant filter is applied before relevance scoring |
| TM-03 | Agent requests a destructive tool | LLM06 Excessive Agency | Every requested action is allowed | Capability allowlist and deny-by-default policy |
| TM-04 | Agent sends an external message | LLM06 Excessive Agency | Message is sent automatically | Human approval is required |
| TM-05 | Sensitive value appears in model context | LLM02 Sensitive Information Disclosure | Secret can be returned by an injected instruction | Real secrets must remain outside prompts and model context |

## Security invariants

- A tenant must never retrieve a document owned by another tenant.
- Untrusted retrieved text must never become a higher-priority instruction.
- The model must not possess credentials required to execute sensitive tools.
- Sensitive actions must be authorized outside the probabilistic model.
- Every tool decision must produce an audit event.

## Out of scope for Phase 1

- Real model-provider APIs
- Real email, payment, database, or operating-system actions
- Production authentication
- Malware generation or execution

