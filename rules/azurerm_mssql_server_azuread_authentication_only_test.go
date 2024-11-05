package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermMsSqlServerAdAuthOnly(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "azuread_authentication_only set to false",
			Content: `
resource "azurerm_mssql_server" "example" {
    azuread_administrator {
        azuread_authentication_only = false
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMsSqlServerAdAuthOnly(),
					Message: "azuread_authentication_only is set to false, should be set to true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   4,
							Column: 39,
						},
						End: hcl.Pos{
							Line:   4,
							Column: 44,
						},
					},
				},
			},
		},
		{
			Name: "azuread_authentication_only set to true",
			Content: `
resource "azurerm_mssql_server" "example" {
    azuread_administrator {
        azuread_authentication_only  = true
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "azuread_authentication_only attribute missing",
			Content: `
resource "azurerm_mssql_server" "example" {
    azuread_administrator {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMsSqlServerAdAuthOnly(),
					Message: "azuread_authentication_only is missing in azuread_administrator, should be set to true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 26,
						},
					},
				},
			},
		},
		{
			Name: "azuread_administrator block missing",
			Content: `
resource "azurerm_mssql_server" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMsSqlServerAdAuthOnly(),
					Message: "azuread_administrator block is missing, azuread_authentication_only should be set to true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 42,
						},
					},
				},
			},
		},
	}

	rule := NewAzurermMsSqlServerAdAuthOnly()

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