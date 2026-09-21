package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestModelToPolicy_OmitsUnsetModules(t *testing.T) {
	m := policyResourceModel{
		Name:             types.StringValue("FedRAMP-IL5 Baseline"),
		AntiMalwareState: types.StringValue("on"),
		FirewallState:    types.StringNull(),
	}
	p := modelToPolicy(m)

	if p.Name != "FedRAMP-IL5 Baseline" {
		t.Fatalf("name = %q, want %q", p.Name, "FedRAMP-IL5 Baseline")
	}
	if p.AntiMalware == nil || p.AntiMalware.State != "on" {
		t.Fatalf("antiMalware = %+v, want state=on", p.AntiMalware)
	}
	if p.Firewall != nil {
		t.Fatalf("firewall = %+v, want nil (unset must not be sent)", p.Firewall)
	}
}

func TestPolicyToModel_RoundTrip(t *testing.T) {
	p := &Policy{
		ID:          42,
		Name:        "Base child",
		ParentID:    1,
		Firewall:    &ModuleState{State: "detect"},
		AntiMalware: &ModuleState{State: "on"},
	}
	m := policyToModel(p)

	if m.ID.ValueString() != "42" {
		t.Fatalf("id = %q, want 42", m.ID.ValueString())
	}
	if m.ParentID.ValueInt64() != 1 {
		t.Fatalf("parent_id = %d, want 1", m.ParentID.ValueInt64())
	}
	if m.FirewallState.ValueString() != "detect" {
		t.Fatalf("firewall_state = %q, want detect", m.FirewallState.ValueString())
	}
	if !m.WebReputationState.IsNull() {
		t.Fatalf("web_reputation_state = %q, want null", m.WebReputationState.ValueString())
	}
}

func TestPolicyToModel_ZeroParentIsNull(t *testing.T) {
	m := policyToModel(&Policy{ID: 7, Name: "top", ParentID: 0})
	if !m.ParentID.IsNull() {
		t.Fatalf("parent_id = %d, want null when ParentID is 0", m.ParentID.ValueInt64())
	}
}

func TestStringOneOf(t *testing.T) {
	moduleCases := map[string]bool{
		"on": true, "off": true, "inherited": true,
		"detect": false, "prevent": false, "enabled": false, "On": false, "": false,
	}
	for in, wantValid := range moduleCases {
		var resp validator.StringResponse
		stringOneOf{moduleStateValues}.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("firewall_state"),
			ConfigValue: types.StringValue(in),
		}, &resp)
		if got := !resp.Diagnostics.HasError(); got != wantValid {
			t.Errorf("module state %q: valid=%v, want %v", in, got, wantValid)
		}
	}

	engineCases := map[string]bool{
		"Tap": true, "Inline": true,
		"tap": false, "inline": false, "detect": false, "": false,
	}
	for in, wantValid := range engineCases {
		var resp validator.StringResponse
		stringOneOf{engineModeValues}.ValidateString(context.Background(), validator.StringRequest{
			Path:        path.Root("network_engine_mode"),
			ConfigValue: types.StringValue(in),
		}, &resp)
		if got := !resp.Diagnostics.HasError(); got != wantValid {
			t.Errorf("engine mode %q: valid=%v, want %v", in, got, wantValid)
		}
	}

	// IPS allows detect/prevent; standard modules do not.
	ipsCases := map[string]bool{"detect": true, "prevent": true, "off": true, "inherited": true, "on": false, "real-time": false}
	for in, wantValid := range ipsCases {
		var resp validator.StringResponse
		stringOneOf{ipsStateValues}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("intrusion_prevention_state"), ConfigValue: types.StringValue(in),
		}, &resp)
		if got := !resp.Diagnostics.HasError(); got != wantValid {
			t.Errorf("ips state %q: valid=%v, want %v", in, got, wantValid)
		}
	}

	// Integrity Monitoring allows real-time.
	imCases := map[string]bool{"real-time": true, "on": true, "off": true, "inherited": true, "detect": false}
	for in, wantValid := range imCases {
		var resp validator.StringResponse
		stringOneOf{integrityStateValues}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("integrity_monitoring_state"), ConfigValue: types.StringValue(in),
		}, &resp)
		if got := !resp.Diagnostics.HasError(); got != wantValid {
			t.Errorf("im state %q: valid=%v, want %v", in, got, wantValid)
		}
	}
}

func TestNetworkEngineModeMapping(t *testing.T) {
	// Set -> sent as a policy setting.
	p := modelToPolicy(policyResourceModel{
		Name:              types.StringValue("p"),
		NetworkEngineMode: types.StringValue("Tap"),
	})
	if sv, ok := p.PolicySettings[settingNetworkEngineMode]; !ok || sv.Value != "Tap" {
		t.Fatalf("policySettings[%s] = %+v, want Tap", settingNetworkEngineMode, p.PolicySettings)
	}

	// Unset -> no policySettings sent (DSM keeps its value).
	if p := modelToPolicy(policyResourceModel{Name: types.StringValue("p")}); p.PolicySettings != nil {
		t.Fatalf("policySettings = %+v, want nil when unset", p.PolicySettings)
	}

	// Read back from a full policy -> extracted into the model.
	m := policyToModel(&Policy{
		ID: 5, Name: "p",
		PolicySettings: map[string]SettingValue{settingNetworkEngineMode: {Value: "Inline"}},
	})
	if m.NetworkEngineMode.ValueString() != "Inline" {
		t.Fatalf("network_engine_mode = %q, want Inline", m.NetworkEngineMode.ValueString())
	}
}
