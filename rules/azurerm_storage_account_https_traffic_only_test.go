package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermStorageAccountHTTPSTrafficOnlyEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "https_traffic_only_enabled disabled",
			Content: `
resource "azurerm_storage_account" "example" {
    https_traffic_only_enabled = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountHTTPSTrafficOnlyEnabled(),
					Message: "https_traffic_only_enabled should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 34},
						End:      hcl.Pos{Line: 3, Column: 39},
					},
				},
			},
		},
		{
			Name: "https_traffic_only attribute missing",
			Content: `
resource "azurerm_storage_account" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountHTTPSTrafficOnlyEnabled(),
					Message: "https_traffic_only_enabled is not defined and should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 45},
					},
				},
			},
		},
		{
			Name: "https_traffic_only_enabled enabled",
			Content: `
resource "azurerm_storage_account" "example" {
    https_traffic_only_enabled = true
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermStorageAccountHTTPSTrafficOnlyEnabled()

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
