package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermMsSQLServerUnsecureTLS(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "insecure TLS version found",
			Content: `
resource "azurerm_mssql_server" "example" {
    min_tls_version = "1.0"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMsSQLServerUnsecureTLS(),
					Message: `"1.0" is an insecure value as min_tls_version`,
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 23},
						End:      hcl.Pos{Line: 3, Column: 28},
					},
				},
			},
		},
		{
			Name: "secure TLS version",
			Content: `
resource "azurerm_mssql_server" "example" {
    min_tls_version = "1.2"
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermMsSQLServerUnsecureTLS()

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
