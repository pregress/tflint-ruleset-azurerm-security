package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermEventhubNamespacePublicNetworkAccessEnabled(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "public network access disabled",
			Content: `
resource "azurerm_eventhub_namespace" "example" {
    public_network_access_enabled = true
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermEventhubNamespacePublicNetworkAccessEnabled(),
					Message: "Consider changing public_network_access_enabled to false",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 37},
						End:      hcl.Pos{Line: 3, Column: 41},
					},
				},
			},
		},
		{
			Name: "public network access missing",
			Content: `
resource "azurerm_eventhub_namespace" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermEventhubNamespacePublicNetworkAccessEnabled(),
					Message: "public_network_access_enabled is not defined and defaults to true, consider disabling it",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 48},
					},
				},
			},
		},
		{
			Name: "public network access disabled",
			Content: `
resource "azurerm_eventhub_namespace" "example" {
    public_network_access_enabled = false
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermEventhubNamespacePublicNetworkAccessEnabled()

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
