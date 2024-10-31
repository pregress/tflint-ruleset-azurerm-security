package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermWindowsWebAppFtpsState(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "FTPS enabled",
			Content: `
resource "azurerm_windows_web_app" "example" {
    ftps_state = "Enabled"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppFtpsState(),
					Message: `ftps_state is set to "Enabled", should be Disabled`,
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 18},
						End:      hcl.Pos{Line: 3, Column: 27},
					},
				},
			},
		},
		{
			Name: "FTPS state missing",
			Content: `
resource "azurerm_windows_web_app" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppFtpsState(),
					Message: `ftps_state should be set to Disabled`,
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 45},
					},
				},
			},
		},
		{
			Name: "FTPS disabled",
			Content: `
resource "azurerm_windows_web_app" "example" {
    ftps_state = "Disabled"
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermWindowsWebAppFtpsState()

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

