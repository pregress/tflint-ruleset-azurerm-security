package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermStorageAccountDefaultToOAuthAuthentication(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "default_to_oauth_authentication is not defined",
			Content: `
resource "azurerm_storage_account" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountDefaultToOAuthAuthentication(),
					Message: "default_to_oauth_authentication is not defined and should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 45},
					},
				},
			},
		},
		{
			Name: "default_to_oauth_authentication is false",
			Content: `
resource "azurerm_storage_account" "example" {
  default_to_oauth_authentication = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountDefaultToOAuthAuthentication(),
					Message: "default_to_oauth_authentication should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 42},
					},
				},
			},
		},
		{
			Name: "default_to_oauth_authentication is true",
			Content: `
resource "azurerm_storage_account" "example" {
  default_to_oauth_authentication = true
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple storage accounts with mixed settings",
			Content: `
resource "azurerm_storage_account" "example1" {
  default_to_oauth_authentication = true
}

resource "azurerm_storage_account" "example2" {
  default_to_oauth_authentication = false
}

resource "azurerm_storage_account" "example3" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountDefaultToOAuthAuthentication(),
					Message: "default_to_oauth_authentication should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 7, Column: 37},
						End:      hcl.Pos{Line: 7, Column: 42},
					},
				},
				{
					Rule:    NewAzurermStorageAccountDefaultToOAuthAuthentication(),
					Message: "default_to_oauth_authentication is not defined and should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 10, Column: 1},
						End:      hcl.Pos{Line: 10, Column: 46},
					},
				},
			},
		},
	}

	rule := NewAzurermStorageAccountDefaultToOAuthAuthentication()

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
