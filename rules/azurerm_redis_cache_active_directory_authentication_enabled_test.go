package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermRedisCacheAADAuhtenticationEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "active_directory_authentication_enabled disabled",
			Content: `
resource "azurerm_redis_cache" "example" {
    active_directory_authentication_enabled = false
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheAADAuhtenticationEnabled(),
					Message: "active_directory_authentication_enabled should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 47},
						End:      hcl.Pos{Line: 3, Column: 52},
					},
				},
			},
		},
		{
			Name: "active_directory_authentication_enabled attribute missing",
			Content: `
resource "azurerm_redis_cache" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheAADAuhtenticationEnabled(),
					Message: "active_directory_authentication_enabled is not defined and should be true",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 41},
					},
				},
			},
		},
		{
			Name: "active_directory_authentication_enabled enabled",
			Content: `
resource "azurerm_redis_cache" "example" {
    active_directory_authentication_enabled = true
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermRedisCacheAADAuhtenticationEnabled()

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
