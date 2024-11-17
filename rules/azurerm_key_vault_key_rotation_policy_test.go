package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultKeyRotationPolicy(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "rotation_policy with expire_after properly configured",
			Content: `
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
        expire_after = "P90D"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "rotation_policy with expire_after set to different duration",
			Content: `
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
        expire_after = "P6M"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "rotation_policy block missing",
			Content: `
resource "azurerm_key_vault_key" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultKeyRotationPolicy(),
					Message: "rotation_policy block is missing, should be defined with expire_after property",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 43,
						},
					},
				},
			},
		},
		{
			Name: "expire_after property missing",
			Content: `
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultKeyRotationPolicy(),
					Message: "expire_after is missing in rotation_policy block",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 20,
						},
					},
				},
			},
		},
		{
			Name: "rotation_policy with empty expire_after value",
			Content: `
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
        expire_after = ""
    }
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermKeyVaultKeyRotationPolicy()

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