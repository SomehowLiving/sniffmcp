# Security policy

## Reporting a vulnerability in sniffmcp

Please **don't open a public issue**. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. We aim to acknowledge reports within 3 days and to agree on a fix and
disclosure timeline with you.

Especially in scope, because they are the guarantees this tool makes:

- A way to make sniffmcp **execute code** it shouldn't: launching a package flagged as
  known malware, or running arbitrary commands through MCP server mode without
  `SNIFFMCP_ALLOW_COMMANDS=1`
- A way to make the crawler contact **non-public addresses** (SSRF), or call a tool instead
  of only listing
- **Secrets leaking** into reports, SARIF, logs or the local databases' exported output
- Text in a scanned server's metadata that manipulates sniffmcp's own output or an agent
  reading it

## How we handle findings about other people's servers

The crawler observes public MCP servers and packages. When it surfaces something that looks
malicious:

1. We check it by hand first. Automated hits are leads, not verdicts.
2. We report it privately to the maintainer (and to the registry or package registry when
   the risk is active, e.g. via OSV/OpenSSF malicious-packages) before saying anything publicly.
3. We publish facts ("this description gained this instruction on this date"), not labels
   like "malicious", unless an advisory already exists.

If you maintain a server and believe the crawler treated it unfairly or too often, open an
issue or contact us privately and we'll fix or exclude it.
