# Secure Coding Review — VitaBank Sample Banking Portal

> CodeAlpha Cyber Security Internship — Secure Coding Review
> Conducted by **Amantle Maakelo**

A complete secure code review workflow: a deliberately-vulnerable Flask
"internal banking portal" sample app, a professional-format audit report
identifying 10 real vulnerabilities (manually reviewed + confirmed with
Bandit static analysis), and a fully remediated version of the code,
**re-scanned to verify the fixes actually work.**

## Why this framing

Internal financial tools are often built fast, by small teams, without a
formal security review and that's exactly where serious vulnerabilities
slip through. Rather than review a toy "hello world" app, this project
audits a small transaction-handling application (login, fund transfers,
account statements, admin panel), the same feature set as countless real
internal banking tools — so the findings actually reflect what a reviewer
would encounter in a banking or fintech environment.

## What's in this repo

```
CodeAlpha_SecureCodingReview/
├── README.md
├── audit-target/
│   ├── app.py              # the AS-FOUND vulnerable application
│   └── requirements.txt
├── fixed-code/
│   ├── app.py               # the REMEDIATED application
│   ├── templates/           # Jinja2 templates (autoescaping enabled)
│   └── requirements.txt
└── docs/
    ├── AUDIT_REPORT.md       # full findings report (start here)
    ├── bandit_raw_output.txt   # Bandit scan of the vulnerable version
    └── bandit_fixed_output.txt # Bandit scan of the fixed version (0 issues)
```

**Start with [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md)** — it's the
main deliverable and reads like a professional security audit report.

## Findings at a glance

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 5 |
| Medium | 1 |
| Low | 1 |

Covers SQL injection, broken access control, weak cryptography, reflected
XSS, missing CSRF protection, path traversal, and security
misconfiguration , mapped to both CWE and OWASP Top 10 (2021) categories.

## Methodology

1. **Manual review** of every route using the OWASP Top 10 as a checklist
2. **Automated static analysis** with [Bandit](https://bandit.readthedocs.io/)
   to cross-check and catch anything missed
3. **Remediation** using framework-native, industry-standard controls
   (parameterized queries, `werkzeug.security` password hashing,
   `Flask-WTF` CSRF protection, Jinja2 autoescaping, proper access-control
   decorators)
4. **Re-verification** — Bandit re-run against the fixed code confirms
   **zero remaining issues**, so the fix is demonstrated, not just claimed

## Running it yourself

```bash
# Vulnerable version (for review/demo purposes only — do not expose publicly)
cd audit-target
pip install -r requirements.txt
python3 app.py

# Fixed version
cd fixed-code
pip install -r requirements.txt
export VITABANK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export VITABANK_ADMIN_BOOTSTRAP_PASSWORD="ChangeMe123!"
python3 app.py
```

To reproduce the static analysis:

```bash
pip install bandit
bandit audit-target/app.py
bandit fixed-code/app.py
```

## What this demonstrates

- Ability to read and reason about real application code through a
  security lens, not just run a scanner and copy-paste output
- Familiarity with the OWASP Top 10 and CWE classification, and how to
  communicate findings clearly to a technical or non-technical audience
- Practical remediation skills , not just "this is bad" but concrete,
  framework-appropriate fixes
- A verification mindset: claims are backed by a re-scan, matching how a
  real audit would close out findings

## Legal & ethical note

`audit-target/app.py` is intentionally vulnerable and built solely for
this educational audit exercise. It should never be deployed to a public
or production environment.

## Author

**Amantle Maakelo** 
Pivoting into Cybersecurity & SAP 
[GitHub](https://github.com/amantlemaakelo)
