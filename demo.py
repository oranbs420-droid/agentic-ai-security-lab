"""Run a quick vulnerable-versus-secure demonstration."""

from agentic_security_lab import AgenticSecurityLab


def print_result(title: str, result: object) -> None:
    print(f"\n=== {title} ===")
    print(result)


def main() -> None:
    lab = AgenticSecurityLab()

    print_result(
        "VULNERABLE: indirect prompt injection",
        lab.chat("When are benefits reviewed?", tenant_id="alpha", secure=False),
    )
    print_result(
        "SECURE: untrusted document excluded",
        lab.chat("When are benefits reviewed?", tenant_id="alpha", secure=True),
    )
    print_result(
        "VULNERABLE: excessive agency",
        lab.request_action("delete_customer_database", "production", "viewer", secure=False),
    )
    print_result(
        "SECURE: capability enforcement",
        lab.request_action("delete_customer_database", "production", "viewer", secure=True),
    )


if __name__ == "__main__":
    main()

