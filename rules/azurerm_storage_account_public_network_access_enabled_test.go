package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermStorageAccountPublicNetworkAccessEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "public network access enabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 41},
					},
				},
			},
		},
		{
			Name: "public network access missing",
			Content: `
resource "azurerm_storage_account" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "public_network_access is not defined and defaults to Enabled, consider setting it to Disabled or SecuredByPerimeter, or adding network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 45},
					},
				},
			},
		},
		{
			Name: "public network access disabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = false
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "public network access enabled netork rules with default_action = Deny",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true

	network_rules {
		default_action             = "Deny"
		bypass                     = ["AzureServices"]
		ip_rules = ["1.1.1.1"]
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "public network access enbled network rules with default_action = Allow",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true

	network_rules {
		default_action             = "Allow"
		bypass                     = ["AzureServices"]
		ip_rules = ["1.1.1.1"]
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 41},
					},
				},
			},
		},
		{
			Name: "public network access Enabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access = "Enabled"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 29},
						End:      hcl.Pos{Line: 3, Column: 38},
					},
				},
			},
		},
		{
			Name: "public network access Disabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access = "Disabled"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "public network access SecuredByPerimeter",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access = "SecuredByPerimeter"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "legacy enabled but public network access Disabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
    public_network_access         = "Disabled"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "legacy disabled but public network access Enabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = false
    public_network_access         = "Enabled"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "public network access Enabled with network rules default_action = Deny",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access = "Enabled"

	network_rules {
		default_action = "Deny"
	}
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "legacy enabled and public network access Enabled",
			Content: `
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
    public_network_access         = "Enabled"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 41},
					},
				},
				{
					Rule:    NewAzurermStorageAccountPublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 37},
						End:      hcl.Pos{Line: 4, Column: 46},
					},
				},
			},
		},
	}

	rule := NewAzurermStorageAccountPublicNetworkAccessEnabled()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
