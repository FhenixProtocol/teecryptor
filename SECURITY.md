# Security Policy

## Trust model

Teecryptor's security claim is simple: the FHE secret key only ever
materializes inside an attested Intel TDX enclave. The design is built to be
verified, not trusted — the partner-side attestation policy pins the exact
image digest that may reconstruct the key, and this repository is public so
anyone can review the source behind that digest. The trust boundary, threat
model, and what is explicitly out of scope are documented in
[SECURITY-OVERVIEW.md](./SECURITY-OVERVIEW.md). Findings about out-of-scope
items are still welcome; please reference that document.

## Reporting a vulnerability

Report security issues **privately** — do not open a public issue or PR.

- Preferred: GitHub private vulnerability reporting (the repository's
  **Security** tab → "Report a vulnerability").

Include a description, reproduction steps, and impact. We acknowledge reports
promptly and coordinate disclosure with you.

## Security review

This codebase is under continuous security review: every change to a security
control gets adversarial review before it lands, and findings are tracked to
resolution. An independent third-party audit is planned ahead of mainnet, and
its results will be published here.
