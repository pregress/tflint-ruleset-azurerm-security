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
			Name: "ftps_state not set to Disabled",
			Content: `
resource "azurerm_windows_web_app" "example" {
    site_config {
        ftps_state = "FtpsOnly"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppFtpsState(),
					Message: "ftps_state is set to FtpsOnly, should be set to Disabled",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   4,
							Column: 22,
						},
						End: hcl.Pos{
							Line:   4,
							Column: 32,
						},
					},
				},
			},
		},
		{
			Name: "ftps_state set to disabled (lowercase)",
			Content: `
resource "azurerm_windows_web_app" "example" {
    site_config {
        ftps_state = "disabled"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "ftps_state set to DISABLED (uppercase)",
			Content: `
resource "azurerm_windows_web_app" "example" {
    site_config {
        ftps_state = "DISABLED"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "ftps_state attribute missing",
			Content: `
resource "azurerm_windows_web_app" "example" {
    site_config {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppFtpsState(),
					Message: "ftps_state is missing in site_config, should be set to Disabled",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 16,
						},
					},
				},
			},
		},
		{
			Name: "site_config block missing",
			Content: `
resource "azurerm_windows_web_app" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsWebAppFtpsState(),
					Message: "site_config block is missing, ftps_state should be set to Disabled",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 45,
						},
					},
				},
			},
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