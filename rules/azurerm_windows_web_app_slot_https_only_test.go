package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermWindowsWebAppSlotHTTPSOnly(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "https_only disabled",
			Content: `
resource "azurerm_windows_web_app_slot" "example" {
    https_only = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppSlotHTTPSOnly(),
					Message: "https_only should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 18},
						End:      hcl.Pos{Line: 3, Column: 23},
					},
				},
			},
		},
		{
			Name: "https_only attribute missing",
			Content: `
resource "azurerm_windows_web_app_slot" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppSlotHTTPSOnly(),
					Message: "https_only is not defined and should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 50},
					},
				},
			},
		},
		{
			Name: "https_only enabled",
			Content: `
resource "azurerm_windows_web_app_slot" "example" {
    https_only = true
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermWindowsWebAppSlotHTTPSOnly()

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
