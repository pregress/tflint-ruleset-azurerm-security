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
					Message: "Consider changing public_network_access_enabled to false or add network_rules with default_action = \"Deny\"",
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
					Message: "public_network_access_enabled is not defined and defaults to true, consider disabling it or adding network_rules with default_action = \"Deny\"",
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
					Message: "Consider changing public_network_access_enabled to false or add network_rules with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 41},
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
