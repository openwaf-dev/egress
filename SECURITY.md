# Security policy

## Reporting a vulnerability

Email **security@openwaf.dev** with a description, the affected version or commit, and steps to
reproduce. Please do not open a public issue or pull request for a vulnerability. We confirm that we
received the report, keep you informed until a fixed release is published, and
credit reporters in the release notes unless you ask us not to.

## Scope

In scope: the gateway in this repository (agent authentication, target allowlist, SSRF checks,
prompt-injection and DLP inspection, credential injection, request forwarding) and the published
`ghcr.io/openwaf-dev/egress` images.

## Deployment notes

- The gateway speaks plain HTTP and authenticates agents with static placeholder tokens. Bind it to
  loopback or a private network (the default `listen_addr` is `127.0.0.1:8070`), or put TLS in
  front of it; never expose it to the internet.
- Replace the example token `OWE_TOKEN_SUPPORT_AGENT` with a long random value per agent.
- With `enforce_injection` or `block_dlp` on, the text of a body (inline base64 images, audio and video
  excluded) must fit the 1 MiB inspection window or the request is refused with `413`, so no part of a
  body is forwarded uninspected.
- Detection is deterministic pattern matching: it raises the cost of known prompt-injection and
  exfiltration shapes, it does not prove a request is safe.
