package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultPublicNetworkAccessEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "public network access enabled",
			Content: `
resource "azurerm_key_vault" "example" {
    public_network_access_enabled = true
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultPublicNetworkAccessEnabled(),
					Message: "public_network_access_enabled is not defined and defaults to true, consider disabling it or add network_acls block with default_action = Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "public network access missing and network_acls missing",
			Content: `
resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultPublicNetworkAccessEnabled(),
					Message: "public_network_access_enabled is not defined and defaults to true, consider disabling it or add network_acls block with default_action = Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "public network access missing and network_acls empty",
			Content: `
resource "azurerm_key_vault" "example" {
    network_acls {
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultPublicNetworkAccessEnabled(),
					Message: "public_network_access_enabled is not defined and defaults to true, consider disabling it or add network_acls block with default_action = Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "public network access enabled and network_acls default action allow",
			Content: `
resource "azurerm_key_vault" "example" {
    public_network_access_enabled = true
	network_acls {
	    default_action = "Allow"
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultPublicNetworkAccessEnabled(),
					Message: "public_network_access_enabled is true and network_acls block with default_action = Allow, Consider changing the default_action to deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 5, Column: 23},
						End:      hcl.Pos{Line: 5, Column: 30},
					},
				},
			},
		},
		{
			Name: "public network access disabled",
			Content: `
resource "azurerm_key_vault" "example" {
    public_network_access_enabled = false
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "public network access enabled and network_acls default action deny",
			Content: `
resource "azurerm_key_vault" "example" {
    public_network_access_enabled = true
	network_acls {
	    default_action = "Deny"
	}
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermKeyVaultPublicNetworkAccessEnabled()

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
