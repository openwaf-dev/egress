# OpenWAF Cloud data plane mode (egressnode v1)

With `-control-plane`, the gateway runs as a hosted node of OpenWAF Cloud. It polls its
configuration and reports refused requests; it never receives a provider credential from the
control plane. The implementation is `pkg/controlplane`.

## Node identity

`egress keygen -out node.key` writes an ed25519 private key (PKCS#8 PEM, mode 0600) and prints
the public key as standard base64 of the raw 32 bytes. The operator registers it once:

```
POST /v1/egress/nodes {"id":"egress-1","public_key":"<printed value>"}
```

Node ids match `^[a-z0-9][a-z0-9.-]{0,62}$`.

## Request signing (`openwaf-node-request/v1`)

Every request carries:

| Header | Value |
|---|---|
| `X-OpenWAF-Node-ID` | node id |
| `X-OpenWAF-Node-Key-ID` | first 16 hex characters of SHA-256 of the raw public key |
| `X-OpenWAF-Timestamp` | unix seconds (accepted within ±300 s) |
| `X-OpenWAF-Nonce` | 32 lowercase hex characters, single use |
| `X-OpenWAF-Signature` | `ed25519=` + standard base64 of the signature |

The signed input is these lines joined by `\n` (no trailing newline): `openwaf-node-request/v1`,
the method, the escaped path (`/` if empty), the raw query (may be empty), the timestamp, the
nonce, the node id, the key id and the lowercase hex SHA-256 of the body (of the empty string
for a GET). The control plane answers 401 to a bad signature and 403 to an unknown or revoked
node.

## Configuration: `GET /v1/egress/node/config?since_serial=N`

The gateway polls every `-poll-interval` (default 15 s; 1 s doubling up to that after a failure).
`304` means the document in force is current. Redirects are never followed (a `3xx` is an
error). A `200` document:

```json
{"version":1,"node_id":"egress-1","serial":42,"generated_at":"2026-10-27T10:00:00Z","kv_mount":"kv",
 "tenants":[{"org_id":"<uuid>",
   "targets":{"openrouter":{"base_url":"https://openrouter.ai/api/v1","host":"openrouter.ai",
                            "auth_header":"Authorization","auth_prefix":"Bearer ","credential":true}},
   "agents":[{"id":"<uuid>","name":"support-bot","token_sha256":"<sha256 hex of the token>",
              "allowed_targets":["openrouter"],"enforce_injection":true,"block_dlp":true}]}]}
```

- Until a first document arrives, proxied requests answer `503 policy_unavailable`. After that,
  network errors, other non-2xx answers, invalid documents and another node's document keep the
  last good document in force, but only for `-max-stale` (`OPENWAF_MAX_STALE`, default 10 min)
  since the control plane last answered `200` or `304`; past that, requests answer `503` until
  it confirms a document again.
- A `401` or `403` (node revoked, key replaced) withdraws the document at once: requests answer
  `503` until a new document is accepted, starting again from `since_serial=0`.
- A `200` whose `serial` is lower than the one in force is refused; the current document stays.
- `/health` answers `503 {"status":"starting"}` while no usable document is in force, then
  `200 {"status":"ok","service":"openwaf-egress","version":…,"openbao":bool}` (no agent or target
  totals in this mode).
- Invalid tenants, targets (not https, IP literal, userinfo/query/fragment, host not matching
  `base_url`) and agents are skipped with a log line.
- The agent is found by the SHA-256 of the bearer token; the route must be
  `/v1/agent/<that agent's name>/proxy/<target>/…`, otherwise `401`. `X-OpenWAF-Agent` is ignored.
- The upstream key is read from OpenBao KV v2 at mount `kv_mount`, path
  `tenants/<org_id>/egress/<target>`, key `api_key`. The gateway derives this path itself and
  never takes one from the document. Secrets are cached for 5 minutes. A target with
  `"credential": false` is refused (`502 credential_resolution_failed`); the agent token is
  never forwarded upstream.

## Events: `POST /v1/egress/node/events`

Every refused request of an identified agent (`egress_blocked`, `ssrf_blocked`, `body_too_large`,
`injection_detected`, `data_leak_blocked`) becomes one event. Events never include the request
body or any part of it; 401s are not reported (no tenant is known).

```json
{"version":1,"node_id":"egress-1","batch_id":"<uuid v4>","events":[
 {"ts":"2026-10-27T10:00:01Z","org_id":"<uuid>","agent_id":"<uuid>","target":"openrouter",
  "code":"injection_detected","status":403,"method":"POST","path":"/chat/completions",
  "ip":"203.0.113.7","detections":["pi.override.en"]}]}
```

- `method` is upper-cased; anything that is not `^[A-Z]{1,16}$` is sent as `OTHER`.
- `path` is the sub-path after `/proxy/<target>`, without the query, invalid UTF-8, `U+FFFD` or
  non-printable characters, with a leading `/`, at most 2048 bytes.
- `detections` holds up to 16 injection detection ids or DLP match types (`api_key`,
  `private_key`, `credit_card`); it is empty for the other codes.
- `ip` is the connection peer address, or `X-Real-IP` from a `-trusted-proxies` address.
- An event the control plane would refuse (ids, target, status or IP out of shape) is dropped and
  counted rather than sent, so it cannot make its batch answer `422`.
- Events are queued (10000 at most; when full the oldest is dropped and counted) and sent every
  2 s, or as soon as 1000 are waiting, in batches of at most 1000 events and 1 MiB.
- A batch that fails (network error, 5xx, 401/403) is retried with backoff (1 s doubling to
  1 min) under the same `batch_id`, which the control plane deduplicates. A batch refused as
  invalid (400, 413, 422) is dropped and counted. On shutdown the queue is flushed (5 s).
