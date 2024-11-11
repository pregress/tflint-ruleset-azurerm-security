package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultNetworkAclsDefaultDeny(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "no network_acls block",
			Content: `
resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkAclsDefaultDeny(),
					Message: "network_acls block is not defined, consider adding it with default_action = \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "network_acls without default_action",
			Content: `
resource "azurerm_key_vault" "example" {
    network_acls {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkAclsDefaultDeny(),
					Message: "default_action is not defined in network_acls block",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 5},
						End:      hcl.Pos{Line: 3, Column: 17},
					},
				},
			},
		},
		{
			Name: "network_acls with default_action Allow",
			Content: `
resource "azurerm_key_vault" "example" {
    network_acls {
        default_action = "Allow"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkAclsDefaultDeny(),
					Message: "network_acls default_action should be set to \"Deny\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 26},
						End:      hcl.Pos{Line: 4, Column: 33},
					},
				},
			},
		},
		{
			Name: "network_acls with default_action Deny",
			Content: `
resource "azurerm_key_vault" "example" {
    network_acls {
        default_action = "Deny"
    }
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermKeyVaultNetworkAclsDefaultDeny()

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
