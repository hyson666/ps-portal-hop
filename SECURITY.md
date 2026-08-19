# Security Policy

PS Portal Hop is a forward proxy. A publicly reachable proxy can be abused
to relay unwanted traffic or reach services that should remain private.

- Keep `ALLOW_PUBLIC_PROXY=false`.
- Restrict `ALLOWED_CLIENTS` to trusted IP addresses or CIDR ranges.
- On a VPS, apply the same restriction in the cloud firewall or security group.
- Keep `BLOCK_PRIVATE_TARGETS=true` unless you fully understand the SSRF risk.
- Never commit `.env`, credentials, access tokens, or private addresses that
  should not be public.

If changing client IPs require a public listener, use `ALLOW_PUBLIC_RELAY=true`
only with a narrow `ALLOWED_HOSTS` list and the default destination ports
(`443` for CONNECT and `80` for HTTP). Public relay mode also rejects IP-literal
targets and enforces global and per-client connection/request limits. It still
uses the operator's bandwidth and upstream proxy quota, so monitor and size the
limits for your deployment.

To report a vulnerability, use GitHub's private vulnerability reporting for
this repository. Do not include real PlayStation credentials, tokens, or other
people's traffic in a public issue.
