# Security

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on this
repository's Security tab. Please do not open a public issue.

## What this repository is

A companion to a blog series: example code, synthetic data, and tests. It is
not a hosted service and ships no production deployment.

- All policies, agents, hosts, emails and IPs are fictional (`*.internal`,
  `example.com`, RFC 5737 documentation ranges).
- `sentinel serve` binds to `127.0.0.1` by default. Authentication fails
  closed unless Entra ID is configured or `SENTINEL_DEV_MODE=1` is set; never
  set dev mode on a reachable host.
- No credentials are stored here. `examples/phase2/.env.example` holds
  placeholders only; real `.env` files are git-ignored.
