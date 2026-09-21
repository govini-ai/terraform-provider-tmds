package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &policyResource{}
	_ resource.ResourceWithImportState = &policyResource{}
)

func NewPolicyResource() resource.Resource {
	return &policyResource{}
}

type policyResource struct {
	client *Client
}

type policyResourceModel struct {
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	Description              types.String `tfsdk:"description"`
	ParentID                 types.Int64  `tfsdk:"parent_id"`
	AntiMalwareState         types.String `tfsdk:"anti_malware_state"`
	WebReputationState       types.String `tfsdk:"web_reputation_state"`
	FirewallState            types.String `tfsdk:"firewall_state"`
	IntrusionPreventionState types.String `tfsdk:"intrusion_prevention_state"`
	IntegrityMonitoringState types.String `tfsdk:"integrity_monitoring_state"`
	LogInspectionState       types.String `tfsdk:"log_inspection_state"`
	NetworkEngineMode        types.String `tfsdk:"network_engine_mode"`
}

func (r *policyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	// Optional + Computed: the DSM returns a state for every module, so unset
	// attributes adopt the server value instead of showing perpetual drift.
	// Allowed states are per-module (IPS and Integrity Monitoring differ).
	moduleAttr := func(desc string, allowed []string) schema.StringAttribute {
		return schema.StringAttribute{
			MarkdownDescription: desc + " One of `" + strings.Join(allowed, "`, `") + "`.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringOneOf{allowed}},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Deep Security policy (the rulebook). Models module states only; rules/objects are managed by separate resources.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "DSM-assigned policy ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Policy name. Used as the stable identity across managers.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Policy description.",
				Optional:            true,
			},
			"parent_id": schema.Int64Attribute{
				MarkdownDescription: "Parent policy ID to inherit from (e.g. the Base Policy).",
				Optional:            true,
			},
			"anti_malware_state":         moduleAttr("Anti-Malware module state.", moduleStateValues),
			"web_reputation_state":       moduleAttr("Web Reputation module state.", moduleStateValues),
			"firewall_state":             moduleAttr("Firewall module state.", moduleStateValues),
			"intrusion_prevention_state": moduleAttr("Intrusion Prevention module state. `detect` logs, `prevent` blocks.", ipsStateValues),
			"integrity_monitoring_state": moduleAttr("Integrity Monitoring module state.", integrityStateValues),
			"log_inspection_state":       moduleAttr("Log Inspection module state.", moduleStateValues),
			"network_engine_mode": schema.StringAttribute{
				MarkdownDescription: "Firewall/IPS network engine mode. `Tap` = detect-only (inspect and log, never block); `Inline` = prevent (can block). Governs both the Firewall and Intrusion Prevention modules — the detect-first lever.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{stringOneOf{engineModeValues}},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *policyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Policy names are unique per manager. Fail with a clear message instead of a
	// raw 400 if one already exists (e.g. an orphan from a half-applied create).
	existing, err := r.client.SearchPolicyByName(plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error checking for existing policy", err.Error())
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError(
			"Policy already exists",
			fmt.Sprintf("A policy named %q already exists on this manager (ID %d). "+
				"Import it rather than creating it:\n  tofu import <resource address> %d",
				plan.Name.ValueString(), existing.ID, existing.ID),
		)
		return
	}

	created, err := r.client.CreatePolicy(modelToPolicy(plan))
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, policyToModel(created))...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", err.Error())
		return
	}

	policy, err := r.client.GetPolicy(id)
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy", err.Error())
		return
	}
	if policy == nil {
		resp.State.RemoveResource(ctx) // drifted/deleted out-of-band
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, policyToModel(policy))...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.ParseInt(plan.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", err.Error())
		return
	}

	updated, err := r.client.UpdatePolicy(id, modelToPolicy(plan))
	if err != nil {
		resp.Diagnostics.AddError("Error updating policy", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, policyToModel(updated))...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", err.Error())
		return
	}
	if err := r.client.DeletePolicy(id); err != nil {
		resp.Diagnostics.AddError("Error deleting policy", err.Error())
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// --- mapping helpers ---------------------------------------------------------

func moduleState(s types.String) *ModuleState {
	if s.IsNull() || s.IsUnknown() || s.ValueString() == "" {
		return nil
	}
	return &ModuleState{State: s.ValueString()}
}

func stateString(m *ModuleState) types.String {
	if m == nil {
		return types.StringNull()
	}
	return types.StringValue(m.State)
}

func modelToPolicy(m policyResourceModel) *Policy {
	p := &Policy{
		Name:                m.Name.ValueString(),
		Description:         m.Description.ValueString(),
		ParentID:            m.ParentID.ValueInt64(),
		AntiMalware:         moduleState(m.AntiMalwareState),
		WebReputation:       moduleState(m.WebReputationState),
		Firewall:            moduleState(m.FirewallState),
		IntrusionPrevention: moduleState(m.IntrusionPreventionState),
		IntegrityMonitoring: moduleState(m.IntegrityMonitoringState),
		LogInspection:       moduleState(m.LogInspectionState),
	}
	// Send only the settings we manage; the DSM merges them into the policy.
	if s := m.NetworkEngineMode; !s.IsNull() && !s.IsUnknown() && s.ValueString() != "" {
		p.PolicySettings = map[string]SettingValue{
			settingNetworkEngineMode: {Value: s.ValueString()},
		}
	}
	return p
}

func policyToModel(p *Policy) policyResourceModel {
	m := policyResourceModel{
		ID:                       types.StringValue(strconv.FormatInt(p.ID, 10)),
		Name:                     types.StringValue(p.Name),
		AntiMalwareState:         stateString(p.AntiMalware),
		WebReputationState:       stateString(p.WebReputation),
		FirewallState:            stateString(p.Firewall),
		IntrusionPreventionState: stateString(p.IntrusionPrevention),
		IntegrityMonitoringState: stateString(p.IntegrityMonitoring),
		LogInspectionState:       stateString(p.LogInspection),
	}
	if p.Description != "" {
		m.Description = types.StringValue(p.Description)
	} else {
		m.Description = types.StringNull()
	}
	if p.ParentID != 0 {
		m.ParentID = types.Int64Value(p.ParentID)
	} else {
		m.ParentID = types.Int64Null()
	}
	if sv, ok := p.PolicySettings[settingNetworkEngineMode]; ok && sv.Value != "" {
		m.NetworkEngineMode = types.StringValue(sv.Value)
	} else {
		m.NetworkEngineMode = types.StringNull()
	}
	return m
}
