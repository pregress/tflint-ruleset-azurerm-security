package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermRedisCacheMinimumTLSVersion(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "minimum_tls_version below 1.2",
			Content: `
resource "azurerm_redis_cache" "example" {
    minimum_tls_version = "1.0"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheMinimumTLSVersion(),
					Message: "minimum_tls_version is set to 1.0, should be 1.2 or higher",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 27,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 32,
						},
					},
				},
			},
		},
		{
			Name: "minimum_tls_version set to 1.2",
			Content: `
resource "azurerm_redis_cache" "example" {
    minimum_tls_version = "1.2"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "minimum_tls_version attribute missing",
			Content: `
resource "azurerm_redis_cache" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermRedisCacheMinimumTLSVersion(),
					Message: "minimum_tls_version is missing, should be set to 1.2 or higher",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 41,
						},
					},
				},
			},
		},
	}

	rule := NewAzurermRedisCacheMinimumTLSVersion()

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
