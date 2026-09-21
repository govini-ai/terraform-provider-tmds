# The FedRAMP-High / IL5 baseline, modeled as code. Module state is on/off/
# inherited; detect-vs-prevent behavior mode is a separate setting (roadmap).
#
# The parent is resolved by name so the same config applies to any manager
# regardless of that manager's local Base Policy ID.
data "tmds_policy" "base" {
  name = "Base Policy"
}

resource "tmds_policy" "fedramp_il5_baseline" {
  name        = "FedRAMP-IL5 Baseline"
  description = "Managed by terraform-provider-tmds — do not edit in the console."
  parent_id   = tonumber(data.tmds_policy.base.id)

  anti_malware_state         = "on"
  web_reputation_state       = "on"
  firewall_state             = "on"
  intrusion_prevention_state = "on"
  integrity_monitoring_state = "on"
  log_inspection_state       = "on"
}
