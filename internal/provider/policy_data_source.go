package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &policyDataSource{}

func NewPolicyDataSource() datasource.DataSource {
	return &policyDataSource{}
}

type policyDataSource struct {
	client *Client
}

// policyDataSourceModel resolves a policy by name to that manager's local ID.
type policyDataSourceModel struct {
	Name     types.String `tfsdk:"name"`
	ID       types.String `tfsdk:"id"`
	ParentID types.Int64  `tfsdk:"parent_id"`
}

func (d *policyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (d *policyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing Deep Security policy by name and returns this manager's local ID. Use it to reference a parent policy (e.g. `Base Policy`) portably across managers.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact policy name to look up.",
				Required:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "DSM-assigned policy ID on this manager.",
				Computed:            true,
			},
			"parent_id": schema.Int64Attribute{
				MarkdownDescription: "The policy's parent ID, if any.",
				Computed:            true,
			},
		},
	}
}

func (d *policyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *policyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg policyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := d.client.SearchPolicyByName(cfg.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error looking up policy", err.Error())
		return
	}
	if policy == nil {
		resp.Diagnostics.AddError("Policy not found", fmt.Sprintf("no policy named %q on this manager", cfg.Name.ValueString()))
		return
	}

	cfg.ID = types.StringValue(strconv.FormatInt(policy.ID, 10))
	if policy.ParentID != 0 {
		cfg.ParentID = types.Int64Value(policy.ParentID)
	} else {
		cfg.ParentID = types.Int64Null()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
