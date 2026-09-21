# terraform-provider-tmds

A Terraform / OpenTofu provider for **Trend Micro Deep Security (TMDS)** — manage
Deep Security policies declaratively against the DSM REST API.

> **Status: validated against a live DSM, preparing v0.1.0.** The `tmds_policy`
> resource and `tmds_policy` data source are implemented and verified end-to-end
> (create/read/update/delete/import, drift-free). Rule assignment lands in a
> later release. This repo lives **outside** the `infra` monorepo; infra consumes
> it from the registry once published.

## Why a provider (vs. a script)

Each AWS account runs its own independent DSM, and Deep Security 20 has no native
cross-manager sync. A provider makes policy **declarative** (plan/state/drift),
and per-manager state resolves rule **names → that manager's local IDs** — the
hard part of doing this with a plain script. Modeled on the open-source
[`terraform-provider-pritunl`](https://github.com/govini-ai/terraform-provider-pritunl).

## Usage

```hcl
terraform {
  required_providers {
    tmds = {
      source  = "govini-ai/tmds"
      version = "~> 0.1"
    }
  }
}

# Endpoint + key from TMDS_ENDPOINT / TMDS_API_KEY (pull the key from Secrets Manager).
provider "tmds" {
  insecure = true # DSM presents a self-signed cert
}

data "tmds_policy" "base" {
  name = "Base Policy"
}

resource "tmds_policy" "il5_baseline" {
  name                       = "FedRAMP-IL5 Baseline"
  parent_id                  = tonumber(data.tmds_policy.base.id)
  anti_malware_state         = "on"
  intrusion_prevention_state = "detect" # detect-first; flip to "prevent" after canary
  network_engine_mode        = "Inline"
}
```

Module states are per-module: Intrusion Prevention accepts
`prevent/detect/off/inherited`, Integrity Monitoring accepts
`real-time/on/off/inherited`, the rest `on/off/inherited`. See `docs/`.

## Layout

```
.
├── main.go                              # provider entrypoint
├── internal/provider/
│   ├── provider.go                      # provider schema + configuration
│   ├── client.go                        # DSM REST client
│   ├── policy_resource.go               # tmds_policy resource (CRUD + import)
│   ├── policy_data_source.go            # tmds_policy data source (name→ID)
│   └── validators.go                    # per-module state enums
├── docs/                                # generated provider docs (tfplugindocs)
├── examples/                            # example HCL
├── .goreleaser.yml                      # release build/sign config
├── .github/workflows/release.yml        # publishes a signed GitHub Release on tag
└── terraform-registry-manifest.json     # registry protocol manifest
```

## Local development (no GitHub / registry needed)

```bash
mise run build          # go build
mise run test           # unit tests
mise run install-local  # build + install for dev_overrides
```

Point Terraform/OpenTofu at the local build via `~/.terraformrc` (or `~/.tofurc`):

```hcl
provider_installation {
  dev_overrides {
    "govini-ai/tmds" = "/Users/<you>/.terraform.d/plugins/registry.terraform.io/govini-ai/tmds/0.0.1/<os>_<arch>"
  }
  direct {}
}
```

Then in a scratch dir set `TMDS_ENDPOINT` / `TMDS_API_KEY` and run `tofu plan`
against a **test/canary DSM** (never prod first). Skip `init` while dev_overrides
is active.

## Scope

- `tmds_policy` — the rulebook: module states + `network_engine_mode`. **Implemented.**
- `data "tmds_policy"` — name→ID lookup. **Implemented.**
- Rule assignment (`tmds_policy_*_rules`), rule lookup data sources, and
  `tmds_event_based_task` — planned for a later release.

## Releasing

Docs are generated with `tfplugindocs generate`. A tagged push (`vX.Y.Z`) runs
GoReleaser via GitHub Actions to build and GPG-sign a release; the Terraform and
OpenTofu registries index it. Requires `GPG_PRIVATE_KEY` / `GPG_FINGERPRINT`
repository secrets and the public key registered with the registry.
