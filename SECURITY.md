# Security policy

RSI is pre-alpha software. It is not ready to custody funds or execute live transactions.

## Non-negotiable boundaries

- Never use a primary human wallet or primary Robinhood account as RSI's execution account.
- Keep research, evaluation, signing, and execution in separate capability domains.
- Do not put raw external content into a signer prompt or transaction builder.
- Do not auto-install or auto-authorize tools discovered through ERC-8004, ERC-8257, MCP, x402, X, or any marketplace.
- Treat payment receipts, reputation records, verification badges, and registry entries as provenance—not proof of truth or safety.

## Reporting

Do not include exploitable details, credentials, private data, or unredacted
reproductions in a public issue. Use GitHub's **Report a vulnerability** flow under
the repository Security tab so the report reaches the maintainer privately.

Include the smallest sanitized reproduction that establishes impact. If private
vulnerability reporting is unavailable, open a public issue containing only a
request for a private contact channel—never the vulnerability details.
