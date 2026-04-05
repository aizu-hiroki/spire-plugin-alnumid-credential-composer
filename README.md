# spire-plugin-alnumid-credential-composer

![Test](https://github.com/aizu-hiroki/spire-plugin-alnumid-credential-composer/actions/workflows/test.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](go.mod)

> **⚠️ EXPERIMENTAL — USE AT YOUR OWN RISK**
>
> This project is experimental and provided "as-is" without any warranty or
> guarantee of any kind. It has not been audited for security and is not
> intended for production use. The authors and contributors accept no
> responsibility or liability for any damages, data loss, security incidents,
> or other consequences arising from the use of this software. **You use this
> software entirely at your own risk.**

> This is an **unofficial** community plugin and is not affiliated with or
> endorsed by SPIFFE, SPIRE, or the CNCF.

---

A [SPIRE](https://github.com/spiffe/spire) CredentialComposer plugin that adds
a structured alphanumeric identifier derived from a workload's SPIFFE ID as a
custom claim in JWT-SVIDs.

The identifier is formed by independently SHA256-hashing the trust domain and
path portions of the SPIFFE ID and concatenating the results. Because the two
portions are hashed separately, workloads from different trust domains can
**never** produce the same identifier prefix, making cross-domain collision
attacks structurally impossible.

## How it works

```
spiffe://org-a.example/workload/service-a
  │                     │
  │  SHA256[:N chars]   │  SHA256[:M chars]
  ▼                     ▼
"a1b2c3d4e5f6a7b8" + "1234567890abcdef"
  └──────────────────────────────────┘
          custom JWT-SVID claim
```

Resulting JWT-SVID payload example (N=16, M=16):

```json
{
  "sub": "spiffe://org-a.example/workload/service-a",
  "aud": ["spiffe://org-a.example"],
  "uid": "a1b2c3d4e5f6a7b81234567890abcdef"
}
```

## Requirements

- Go 1.26+
- SPIRE v1.x (with CredentialComposer plugin support)
- Linux / macOS / Windows (amd64, arm64)

## Build

```bash
go mod tidy
go build -o spire-plugin-alnumid-credential-composer .
```

## Configuration

Add the plugin to your SPIRE Server configuration (`spire-server.conf`):

```hcl
plugins {
    CredentialComposer "alnumid_composer" {
        plugin_cmd      = "/usr/local/bin/spire-plugin-alnumid-credential-composer"
        plugin_checksum = "sha256:<sha256sum of binary>"
        plugin_data {
            # Name of the custom claim added to JWT-SVIDs.
            # Default: "uid"
            claim_name = "uid"

            # Number of hex characters from the SHA256 of the trust domain.
            # Must be a positive even number, max 64. Default: 16
            domain_chars = 16

            # Number of hex characters from the SHA256 of the path.
            # Must be a positive even number, max 64. Default: 16
            path_chars = 16
        }
    }
}
```

### Configuration parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `claim_name` | string | `"uid"` | Name of the custom claim added to JWT-SVIDs |
| `domain_chars` | int | `16` | Hex characters from SHA256 of trust domain (positive even number, max 64) |
| `path_chars` | int | `16` | Hex characters from SHA256 of path (positive even number, max 64) |

Total identifier length = `domain_chars + path_chars`.

## Usage examples

### 32-character identifier

Suitable for systems with a short username or identifier length limit:

```hcl
plugin_data {
    claim_name   = "uid"
    domain_chars = 16
    path_chars   = 16
}
```

### 64-character identifier

```hcl
plugin_data {
    claim_name   = "uid"
    domain_chars = 32
    path_chars   = 32
}
```

### Asymmetric lengths

```hcl
plugin_data {
    claim_name   = "uid"
    domain_chars = 8
    path_chars   = 24
}
```

## Security properties

| Property | Detail |
|----------|--------|
| Cross-domain collision resistance | Structurally impossible — different trust domains always produce different identifier prefixes |
| Within-domain collision resistance | 2⁶⁴ birthday bound (with default 16+16 chars); ~4 billion entries needed for 50% collision probability |
| Hash algorithm | SHA256 (no known practical collision attack) |

## Obtaining the binary checksum

```bash
sha256sum spire-plugin-alnumid-credential-composer
```

Use the output as the `plugin_checksum` value in `spire-server.conf`.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
