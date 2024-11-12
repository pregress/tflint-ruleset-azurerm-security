package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermIoTHubEndpointEventHubAuthenticationType(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "authentication_type not \"identityBased\"",
			Content: `
resource "azurerm_iothub_endpoint_eventhub" "example" {
    authentication_type = "connectionString"
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermIoTHubEndpointEventHubAuthenticationType(),
					Message: "authentication_type should be \"identityBased\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 27},
						End:      hcl.Pos{Line: 3, Column: 45},
					},
				},
			},
		},
		{
			Name: "authentication_type attribute missing",
			Content: `
resource "azurerm_iothub_endpoint_eventhub" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermIoTHubEndpointEventHubAuthenticationType(),
					Message: "authentication_type is not defined and should be \"identityBased\"",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 54},
					},
				},
			},
		},
		{
			Name: "authentication_type set to \"identityBased\"",
			Content: `
resource "azurerm_iothub_endpoint_eventhub" "example" {
    authentication_type = "identityBased"
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermIoTHubEndpointEventHubAuthenticationType()

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
