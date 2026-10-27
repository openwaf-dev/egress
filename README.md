<div align="center">

# OpenWAF Egress Gateway

**Zero-trust outbound proxy for AI agents**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg?logo=go)](go.mod)
[![Image](https://img.shields.io/badge/ghcr.io-openwaf--dev%2Fegress-2496ED.svg?logo=docker)](https://github.com/openwaf-dev/egress/pkgs/container/egress)
[![OpenWAF](https://img.shields.io/badge/openwaf.dev-2456e8)](https://openwaf.dev)

[English](#openwaf-egress-gateway) · [Español](#en-español)

<a href="docs/media/egress-cover.mp4"><img src="docs/media/egress-cover.webp" alt="OpenWAF Egress: an agent call with a placeholder token gets the real key injected; prompt injection, card data and SSRF are refused" width="800"></a>

</div>

OpenWAF Egress sits between your AI agents and the model providers they call. Agents hold a
placeholder token instead of the provider key. Every request is checked (agent token, allowed
target, prompt-injection and data-leak patterns), and only then does the gateway fetch the real
key from OpenBao or HashiCorp Vault, inject it, and forward the request with streaming intact.

```
 Agent ── baseURL=http://127.0.0.1:8070/v1/agent/<agent>/proxy/<target>, key=OWE_TOKEN_… ──┐
                                                                                            ▼
 ┌────────────────────────────── OpenWAF Egress ──────────────────────────────┐
 │ 1. agent token          401 if missing or wrong                            │
 │ 2. target allowlist     403 egress_blocked                                 │
 │ 3. SSRF check           403 ssrf_blocked (target resolves to a private IP) │
 │ 4. body inspection      403 injection_detected · 403 data_leak_blocked     │
 │ 5. key from OpenBao     injected into the target's auth header             │
 └────────────────────────────────────────────────────────────────────────────┘
                                                                                            ▼
                                       OpenRouter · OpenAI · Anthropic · Hugging Face · …
```

## What it does

| Risk | What the gateway does |
|---|---|
| Provider keys in agent containers | Agents carry `OWE_TOKEN_…` placeholders. The real key is read from KV v2 (OpenBao or Vault, AppRole login, 5 min cache) and set on the outgoing request only. |
| Prompt injection | 27 deterministic detectors, English and Spanish: 21 pattern detectors (instruction override, system-prompt extraction, jailbreak personas and modes, forged system/tool/turn messages, chat-template tokens, concealment orders, tool invocation and approval bypass, memory poisoning, destructive commands, remote-script piping, secret harvesting, host-data and rendered-link exfiltration, spend amplification) plus 6 for hidden or encoded text (zero-width and tag characters, HTML comments, CSS-hidden text, base64, percent/hex). No model call. |
| Data leaks | Payment card numbers (13–19 digits, Luhn-valid), PEM private keys, AWS access key IDs, OpenAI-style `sk-` keys and GitHub tokens. |
| SSRF | The target host must resolve only to public addresses (loopback, RFC 1918, CGNAT, link-local incl. `169.254.169.254`, multicast, reserved and the IPv6 equivalents are refused), and the address actually connected to is checked again, so a name that re-resolves to a private address is refused too. Upstream redirects are never followed: the `3xx` goes back to the agent, so the credential never reaches a host outside the allowlist. Error answers name no resolved address. |
| Partial inspection | Inline images, audio and video are not inspected text: `data:image/…;base64,…` URIs and JSON `"data"` members of ≥ 1 KiB bare base64 (OpenAI `input_audio`, Gemini `inlineData`, Anthropic base64 sources). Everything else must fit the 1 MiB inspection window or the request is refused with `413`. Nothing is forwarded uninspected or cut; bodies are capped at 8 MiB. |

Detection is pattern matching: it stops known injection and exfiltration shapes, it does not prove
a request is safe.

## Performance

Measured with `go test -bench . ./pkg/aiagents/` on an Apple Silicon Mac (darwin/arm64):

| Body | Time per request |
|---|---|
| 4 KB chat request | 84 µs |
| 64 KB chat request | 1.3 ms |
| 64 KB built to trigger every detector (worst case) | 97 ms |

Each detector only runs when one of its keywords is present (`pkg/aiagents/prefilter.go`), so
ordinary traffic skips almost all of them. The static binary is about 7 MB.

## Quickstart

```bash
docker run -d --name openwaf-egress -p 127.0.0.1:8070:8070 \
  -v "$PWD/config.json:/app/config.json:ro" \
  ghcr.io/openwaf-dev/egress:latest
```

Point the agent's SDK at the gateway and give it the placeholder token:

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:8070/v1/agent/my-support-agent/proxy/openrouter",
  apiKey: "OWE_TOKEN_SUPPORT_AGENT", // placeholder; the real key never reaches the agent
});

await client.chat.completions.create({
  model: "openai/gpt-4o-mini",
  messages: [{ role: "user", content: "How do I reset my password?" }],
});
```

## Configuration

See [`config.example.json`](config.example.json).

```json
{
  "listen_addr": "0.0.0.0:8070",
  "openbao": {
    "addr": "https://vault.example.com:8200",
    "ca_file": "/etc/openbao/ca.crt",
    "approle_file": "/run/secrets/egress-approle.json",
    "kv_mount": "secret"
  },
  "targets": {
    "openrouter": { "base_url": "https://openrouter.ai/api/v1", "host": "openrouter.ai" },
    "anthropic": { "base_url": "https://api.anthropic.com/v1", "host": "api.anthropic.com", "auth_header": "x-api-key" },
    "gemini": { "base_url": "https://generativelanguage.googleapis.com", "host": "generativelanguage.googleapis.com", "auth_header": "x-goog-api-key" }
  },
  "agents": {
    "my-support-agent": {
      "token": "OWE_TOKEN_SUPPORT_AGENT",
      "allowed_targets": ["openrouter"],
      "credential_mapping": {
        "openrouter": { "path": "agents/support", "key": "OPENROUTER_API_KEY" }
      },
      "enforce_injection": true,
      "block_dlp": true
    }
  }
}
```

| Field | Default | Notes |
|---|---|---|
| `listen_addr` | `127.0.0.1:8070` | The container image binds `0.0.0.0:8070`; publish it on loopback or a private network only. |
| `openbao.kv_mount` | `kv` | KV v2 mount. A secret is read from `GET /v1/<kv_mount>/data/<path>` (Vault's default mount is `secret`). |
| `openbao.approle_file` | — | JSON `{"role_id": "…", "secret_id": "…"}`; or set `role_id` / `secret_id` inline. |
| `targets.*.auth_header` | `Authorization` | Header that receives the key. The agent's placeholder token (`Authorization: Bearer OWE_…`) is always removed, also for `x-api-key` / `x-goog-api-key` targets. Keys in the query string (`?key=`) are not injected: use the header. |
| `targets.*.auth_prefix` | `Bearer ` for `Authorization`, none otherwise | |
| `agents.*.token` | — | Use a long random value per agent; the example token is public. |
| `agents.*.token_sha256` | — | Instead of `token`: the lowercase hex SHA-256 of the token, so the file holds no token. Tokens are compared in constant time. |

Upstream timeouts: 5 min for the provider's response headers (non-streaming reasoning, image
and video generations), 15 min for a whole exchange including a streamed body.

Blocked requests get JSON such as:

```json
{
  "error": "injection_detected",
  "agent": "my-support-agent",
  "target": "openrouter",
  "detections": [{ "ID": "pi.override.en", "Label": "Instruction override", "Snippet": "Ignore all previous instructions" }]
}
```

## OpenWAF Cloud data plane mode

The same binary can run as a hosted node of [OpenWAF Cloud](https://openwaf.dev): agents,
targets and policies then come from the control plane instead of `config.json`, and every
refused request is reported to the organization's egress events. The config file still sets
`listen_addr` and the OpenBao connection.

```bash
# Once: create the node key and register the printed public key (operator, POST /v1/egress/nodes).
egress keygen -out /etc/openwaf/egress-node.key

egress -config /etc/openwaf/egress.json \
  -control-plane https://app.openwaf.dev -node-id egress-1 \
  -node-key /etc/openwaf/egress-node.key -poll-interval 15s
```

| Flag | Environment | Notes |
|---|---|---|
| `-control-plane` | `OPENWAF_CONTROL_PLANE` | Control plane URL (https). Enables this mode. |
| `-node-id` | `OPENWAF_NODE_ID` | Node id registered with the public key. |
| `-node-key` | `OPENWAF_NODE_KEY` | ed25519 PKCS#8 PEM private key written by `egress keygen` (mode 0600). |
| `-poll-interval` | `OPENWAF_POLL_INTERVAL` | Configuration poll interval, default `15s`. |
| `-max-stale` | `OPENWAF_MAX_STALE` | How long the last configuration stays in force while the control plane cannot confirm it, default `10m`; then requests answer `503` until it can. |
| `-trusted-proxies` | `OPENWAF_TRUSTED_PROXIES` | Comma-separated addresses or CIDRs of reverse proxies in front of the gateway (e.g. `127.0.0.1`): their `X-Real-IP` is the caller address of block events. Works in both modes; default none (the connection address). |

In this mode an agent is identified by its token (looked up by SHA-256) and must call
`/v1/agent/<its name>/proxy/<target>/…`; the agent token is never forwarded upstream, and a
target without a stored credential is refused. If the control plane refuses the node (`401`
or `403`, e.g. revoked), its configuration is dropped at once. `/health` answers
`503 {"status":"starting"}` while no usable configuration is in force, then
`{"status":"ok","service":…,"version":…,"openbao":…}` without agent or target totals. The
protocol (request signing, configuration document, event batches) is described in
[docs/control-plane.md](docs/control-plane.md).

## Security notes

- The gateway speaks plain HTTP and agent tokens are static: keep it on loopback or a private
  network, or put TLS in front of it.
- Report vulnerabilities to **security@openwaf.dev** ([SECURITY.md](SECURITY.md)).

## Build from source

```bash
git clone https://github.com/openwaf-dev/egress.git && cd egress
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o egress ./cmd/egress
./egress -config config.example.json
```

## En español

OpenWAF Egress se coloca entre tus agentes de IA y los proveedores de modelos. El agente solo
tiene un token de marcador (`OWE_TOKEN_…`). La pasarela comprueba cada petición (token del agente,
destino permitido, inyección de prompt y fuga de datos) y solo entonces lee la clave real de
OpenBao o HashiCorp Vault, la inyecta y reenvía la petición con streaming.

- **Inyección de prompt:** 27 detectores deterministas en inglés y español (21 de patrones y 6 de
  texto oculto o codificado), sin llamar a ningún modelo.
- **Fuga de datos:** tarjetas válidas por Luhn, claves privadas PEM, claves de AWS, claves `sk-`
  de OpenAI y tokens de GitHub.
- **SSRF:** el destino solo puede resolver a direcciones públicas (también se comprueba la dirección
  a la que se conecta de verdad), y la pasarela nunca sigue una redirección del proveedor: el `3xx`
  vuelve al agente y la clave no sale hacia otro host.
- **Cuerpos grandes:** las imágenes, audios y vídeos en línea no cuentan (URI `data:image/…;base64,…`
  y miembros JSON `"data"` con ≥ 1 KiB de base64: `input_audio` de OpenAI, `inlineData` de Gemini,
  fuentes base64 de Anthropic); el resto del texto debe caber en 1 MiB o se rechaza con `413`.
  Nunca se reenvía nada sin inspeccionar.
- **Rendimiento:** 84 µs por una petición de chat de 4 KB (Mac con Apple Silicon, darwin/arm64).

**Modo plano de datos de OpenWAF Cloud:** con `-control-plane https://app.openwaf.dev`,
`-node-id` y `-node-key` (o `OPENWAF_CONTROL_PLANE`, `OPENWAF_NODE_ID`, `OPENWAF_NODE_KEY`;
`-poll-interval`/`OPENWAF_POLL_INTERVAL`, 15 s por defecto) la pasarela toma agentes, destinos y
políticas del panel de control en lugar de `config.json` (que sigue fijando `listen_addr` y
OpenBao) y le envía cada petición bloqueada. La última configuración sigue vigente como mucho
`-max-stale` (`OPENWAF_MAX_STALE`, 10 min por defecto) sin confirmación del panel; después, y en
cuanto el panel rechaza el nodo (`401`/`403`), las peticiones responden `503` y `/health` responde
`503 {"status":"starting"}`. Detrás de un proxy inverso, `-trusted-proxies 127.0.0.1`
(`OPENWAF_TRUSTED_PROXIES`) toma la IP del cliente de su `X-Real-IP`. `egress keygen -out node.key` crea la clave del nodo
e imprime la clave pública que el operador registra. Detalles del protocolo en
[docs/control-plane.md](docs/control-plane.md).

Expón la pasarela solo en loopback o en una red privada. Vulnerabilidades:
**security@openwaf.dev**.

## License

[Apache License 2.0](LICENSE).
