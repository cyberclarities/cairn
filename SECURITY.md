# Security Policy

CAIRN handles incident case data, evidence, and credentials for connected security tools. If you find
a vulnerability, please report it privately rather than through a public GitHub issue.

## Reporting

Email **security@cyberclarities.com** with:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept
- The affected version or commit

You should get an acknowledgment within a few days. Please give us a reasonable window to ship a fix
before any public disclosure.

## Supported versions

CAIRN does not yet have tagged releases. Until it does, only the `main` branch is supported —
report issues against the latest commit.

## Scope

In scope: the Flask application, the Docker/Compose deployment, and the CrowdStrike/Proofpoint
integration code in this repository.

Out of scope: vulnerabilities in third-party dependencies (report those upstream, though we'd
appreciate a heads-up so we can pin a fix) and vulnerabilities requiring an already-compromised admin
account.
