package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermRedisCacheNonSSLPortEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "non_ssl_port_enabled enabled",
			Content: `
resource "azurerm_redis_cache" "example" {
    non_ssl_port_enabled = true
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheNonSSLPortEnabled(),
					Message: "non_ssl_port_enabled should be false",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 28},
						End:      hcl.Pos{Line: 3, Column: 32},
					},
				},
			},
		},
		{
			Name: "non_ssl_port_enabled attribute missing",
			Content: `
resource "azurerm_redis_cache" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheNonSSLPortEnabled(),
					Message: "non_ssl_port_enabled is not defined and should be false",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 41},
					},
				},
			},
		},
		{
			Name: "non_ssl_port_enabled disabled",
			Content: `
resource "azurerm_redis_cache" "example" {
    non_ssl_port_enabled = false
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermRedisCacheNonSSLPortEnabled()

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
