package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the provider satisfies the framework interface.
var _ provider.Provider = &tmdsProvider{}

type tmdsProvider struct {
	version string
}

// New returns a provider factory for the given build version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &tmdsProvider{version: version}
	}
}

type tmdsProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIKey   types.String `tfsdk:"api_key"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

func (p *tmdsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "tmds"
	resp.Version = p.version
}

func (p *tmdsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Trend Micro Deep Security (TMDS) policies declaratively via the DSM REST API.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "DSM REST API base URL, e.g. `https://dsm.example.com`. May also be set via `TMDS_ENDPOINT`.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "DSM API secret key. May also be set via `TMDS_API_KEY`. Pull from Secrets Manager — never hardcode.",
				Optional:            true,
				Sensitive:           true,
			},
			"insecure": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS verification. DSM often presents a self-signed cert; prefer a CA bundle in prod.",
				Optional:            true,
			},
		},
	}
}

func (p *tmdsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg tmdsProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv("TMDS_ENDPOINT")
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	apiKey := os.Getenv("TMDS_API_KEY")
	if !cfg.APIKey.IsNull() {
		apiKey = cfg.APIKey.ValueString()
	}

	if endpoint == "" {
		resp.Diagnostics.AddError("Missing endpoint", "Set the provider `endpoint` or the TMDS_ENDPOINT env var.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddError("Missing api_key", "Set the provider `api_key` or the TMDS_API_KEY env var.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client := NewClient(endpoint, apiKey, cfg.Insecure.ValueBool())
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *tmdsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPolicyResource,
	}
}

func (p *tmdsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewPolicyDataSource,
	}
}
