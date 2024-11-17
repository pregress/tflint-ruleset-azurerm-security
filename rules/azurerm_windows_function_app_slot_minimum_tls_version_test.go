package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermWindowsFunctionAppSlotMinimumTLSVersion(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "minimum_tls_version below 1.2",
			Content: `
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
        minimum_tls_version = "1.0"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
					Message: "minimum_tls_version is set to 1.0, should be 1.2 or higher",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   4,
							Column: 31,
						},
						End: hcl.Pos{
							Line:   4,
							Column: 36,
						},
					},
				},
			},
		},
		{
			Name: "minimum_tls_version set to 1.2",
			Content: `
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
        minimum_tls_version = "1.2"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "minimum_tls_version attribute missing",
			Content: `
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
					Message: "minimum_tls_version is missing in site_config, should be set to 1.2 or higher",
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
resource "azurerm_windows_function_app_slot" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
					Message: "site_config block is missing, minimum_tls_version should be set to 1.2 or higher",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 55,
						},
					},
				},
			},
		},
		{
			Name: "minimum_tls_version set to 1.3",
			Content: `
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
        minimum_tls_version = "1.3"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
					Message: "minimum_tls_version is set to 1.3, should be 1.2 or higher",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   4,
							Column: 31,
						},
						End: hcl.Pos{
							Line:   4,
							Column: 36,
						},
					},
				},
			},
		},
	}

	rule := NewAzurermWindowsFunctionAppSlotMinimumTLSVersion()

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