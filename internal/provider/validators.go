package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// stringOneOf restricts a string attribute to a fixed set of values. Implemented
// in-repo to avoid an extra dependency.
type stringOneOf struct {
	allowed []string
}

// DSM enums used by the policy resource. Module-state enums are per-module:
// most are on/off/inherited, but IPS and Integrity Monitoring differ.
var (
	moduleStateValues    = []string{"on", "off", "inherited"}
	ipsStateValues       = []string{"prevent", "detect", "off", "inherited"}
	integrityStateValues = []string{"real-time", "on", "off", "inherited"}
	// Network engine mode governs both Firewall and IPS: Tap = detect-only, Inline = prevent.
	engineModeValues = []string{"Tap", "Inline"}
)

func (v stringOneOf) Description(context.Context) string {
	return fmt.Sprintf("must be one of: %s", strings.Join(v.allowed, ", "))
}

func (v stringOneOf) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v stringOneOf) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	got := req.ConfigValue.ValueString()
	for _, ok := range v.allowed {
		if got == ok {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid value",
		fmt.Sprintf("%q is not valid; %s.", got, v.Description(ctx)),
	)
}
