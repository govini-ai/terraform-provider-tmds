# Resolve an existing policy by name to this manager's local ID. Names are
# stable across managers; IDs are not, so look them up rather than hardcode.
data "tmds_policy" "base" {
  name = "Base Policy"
}

output "base_policy_id" {
  value = data.tmds_policy.base.id
}
