package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermMsSQLFirewallRuleAllAllowed(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "all IPs allowed",
			Content: `
resource "azurerm_mssql_firewall_rule" "example" {
    start_ip_address = "0.0.0.0"
    end_ip_address   = "255.255.255.255"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermMsSQLFirewallRuleAllAllowed(),
					Message: "Firewall rule allows access from all IP addresses (0.0.0.0-255.255.255.255). Consider restricting the IP range for better security.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 49},
					},
				},
			},
		},
		{
			Name: "specific IP range",
			Content: `
resource "azurerm_mssql_firewall_rule" "example" {
    start_ip_address = "10.0.0.0"
    end_ip_address   = "10.0.0.255"
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "missing IP addresses",
			Content: `
resource "azurerm_mssql_firewall_rule" "example" {
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermMsSQLFirewallRuleAllAllowed()

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