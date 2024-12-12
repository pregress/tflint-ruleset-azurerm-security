package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermContainerGroupImageRegistryCredentialIdentity(t *testing.T) {
	rule := NewAzurermContainerGroupImageRegistryCredentialIdentity()

	tests := []struct {
		name     string
		content  string
		expected helper.Issues
	}{
		{
			name: "missing user_assigned_identity_id",
			content: `
resource "azurerm_container_group" "example" {
  image_registry_credential {
    server = "example.azurecr.io"
  }
}`,
			expected: helper.Issues{
				{
					Rule:    rule,
					Message: "user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image for server example.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 3},
						End:      hcl.Pos{Line: 3, Column: 28},
					},
				},
			},
		},
		{
			name: "with user_assigned_identity_id",
			content: `
resource "azurerm_container_group" "example" {
  image_registry_credential {
    server = "example.azurecr.io"
    user_assigned_identity_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test/providers/Microsoft.ManagedIdentity/userAssignedIdentities/test"
  }
}`,
			expected: helper.Issues{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.content})
			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}
			helper.AssertIssues(t, test.expected, runner.Issues)
		})
	}
}
