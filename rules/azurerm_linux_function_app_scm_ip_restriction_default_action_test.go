package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermLinuxFunctionAppScmIPRestrictionDefaultAction(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "scm_ip_restriction_default_action allowed",
			Content: `
resource "azurerm_linux_function_app" "example" {
	site_config {
		scm_ip_restriction_default_action = "Allow"
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermLinuxFunctionAppScmIPRestrictionDefaultAction(),
					Message: "scm_ip_restriction_default_action should be Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 39},
						End:      hcl.Pos{Line: 4, Column: 46},
					},
				},
			},
		},
		{
			Name: "scm_ip_restriction_default_action attribute missing",
			Content: `
resource "azurerm_linux_function_app" "example" {
	site_config {
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermLinuxFunctionAppScmIPRestrictionDefaultAction(),
					Message: "scm_ip_restriction_default_action is not defined and should be Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 48},
					},
				},
			},
		},
		{
			Name: "site_config block missing",
			Content: `
resource "azurerm_linux_function_app" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermLinuxFunctionAppScmIPRestrictionDefaultAction(),
					Message: "scm_ip_restriction_default_action is not defined and should be Deny",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 48},
					},
				},
			},
		},
		{
			Name: "scm_ip_restriction_default_action Deny",
			Content: `
resource "azurerm_linux_function_app" "example" {
    site_config {
        scm_ip_restriction_default_action = "Deny"
    }
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermLinuxFunctionAppScmIPRestrictionDefaultAction()

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
