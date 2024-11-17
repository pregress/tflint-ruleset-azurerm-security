package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultRbacDisabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "rbac disabled",
			Content: `
resource "azurerm_key_vault" "example" {
    enable_rbac_authorization = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultRbacDisabled(),
					Message: "Consider changing enable_rbac_authorization to true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 33},
						End:      hcl.Pos{Line: 3, Column: 38},
					},
				},
			},
		},
		{
			Name: "rbac missing",
			Content: `
resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultRbacDisabled(),
					Message: "enable_rbac_authorization is not defined and defaults to false, consider enabling it",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "rbac enabled",
			Content: `
resource "azurerm_key_vault" "example" {
    enable_rbac_authorization = true
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermKeyVaultRbacDisabled()

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
