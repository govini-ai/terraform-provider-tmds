# terraform-provider-tmds

A Terraform / OpenTofu provider for **Trend Micro Deep Security (TMDS)**. It manages
Deep Security policy declaratively against the Deep Security Manager (DSM) REST API.

## Why a provider

Deep Security has no native cross-manager synchronization: each manager is
independent and assigns its own numeric IDs to policies and rules. Managing policy
with a plain script is awkward — no plan/diff, no state, and no portable way to
reference an object by name across managers. This provider gives declarative
management (plan / apply / drift detection) and keeps per-manager state that resolves
object **names to that manager's local IDs**.

## Requirements

- Terraform >= 1.0 or OpenTofu >= 1.6
- Deep Security Manager 20 with REST API access and an API key
- Go >= 1.23 (only to build from source)

## Using the provider

```hcl
terraform {
  required_providers {
    tmds = {
      source  = "govini-ai/tmds"
      version = "~> 0.1"
    }
  }
}

provider "tmds" {
  endpoint = "https://dsm.example.com" # or TMDS_ENDPOINT
  # api_key sourced from TMDS_API_KEY (mark sensitive; do not hardcode)
  insecure = true # DSM commonly presents a self-signed certificate
}
```

### Provider configuration

| Argument   | Env var         | Description                                   |
| ---------- | --------------- | --------------------------------------------- |
| `endpoint` | `TMDS_ENDPOINT` | DSM REST API base URL                         |
| `api_key`  | `TMDS_API_KEY`  | DSM API secret key (sensitive)                |
| `insecure` | —               | Skip TLS verification (for self-signed certs) |

### Example

```hcl
data "tmds_policy" "base" {
  name = "Base Policy"
}

resource "tmds_policy" "baseline" {
  name                       = "Example Baseline"
  parent_id                  = tonumber(data.tmds_policy.base.id)
  anti_malware_state         = "on"
  intrusion_prevention_state = "detect" # detect-first; "prevent" to enforce
  network_engine_mode        = "Inline"
}
```

Module states are per-module: Intrusion Prevention accepts
`prevent`/`detect`/`off`/`inherited`, Integrity Monitoring accepts
`real-time`/`on`/`off`/`inherited`, and the rest accept `on`/`off`/`inherited`.
See the full reference under [`docs/`](docs/).

## Developing

Build and test with the standard Go toolchain:

```bash
go build ./...
go test ./...
go install .   # installs the provider to $GOPATH/bin
```

To exercise the provider against a DSM before it is published, install the local
build and point Terraform/OpenTofu at it with a development override in
`~/.terraformrc` (or `~/.tofurc`):

```hcl
provider_installation {
  dev_overrides {
    "govini-ai/tmds" = "<directory containing the built provider binary>"
  }
  direct {}
}
```

Then set `TMDS_ENDPOINT` / `TMDS_API_KEY` and run `terraform plan` (skip `init`
while a dev override is active). Always test against a non-production manager first.

## Documentation

Provider documentation lives in [`docs/`](docs/) and is generated from the schema
and examples with [`tfplugindocs`](https://github.com/hashicorp/terraform-plugin-docs):

```bash
tfplugindocs generate --provider-name tmds
```

## Releasing

Pushing a version tag (`vX.Y.Z`) triggers a GitHub Actions workflow that builds all
target platforms and produces a GPG-signed release with
[GoReleaser](https://goreleaser.com); the Terraform and OpenTofu registries index it.
Requires `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` repository secrets and the
corresponding public key registered with the registry.

## License

Mozilla Public License 2.0. See [`LICENSE`](LICENSE).
