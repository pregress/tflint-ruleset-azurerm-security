package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermMssqlDatabaseEncryption(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "encryption disabled",
			Content: `
resource "azurerm_mssql_database" "example" {
    transparent_data_encryption_enabled = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMssqlDatabaseEncryption(),
					Message: "transparent data encryption must be enabled",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 43},
						End:      hcl.Pos{Line: 3, Column: 48},
					},
				},
			},
		},
		{
			Name: "encryption attribute missing",
			Content: `
resource "azurerm_mssql_database" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMssqlDatabaseEncryption(),
					Message: "transparent data encryption is not enabled",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 44},
					},
				},
			},
		},
		{
			Name: "encryption enabled",
			Content: `
resource "azurerm_mssql_database" "example" {
    transparent_data_encryption_enabled = true
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermMssqlDatabaseEncryption()

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
