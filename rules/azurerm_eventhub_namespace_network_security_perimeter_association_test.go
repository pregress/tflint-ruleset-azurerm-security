package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "eventhub namespace without NSP association",
			Content: `
resource "azurerm_eventhub_namespace" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermEventhubNamespaceNetworkSecurityPerimeterAssociation(),
					Message: "EventHub Namespace 'example' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 48},
					},
				},
			},
		},
		{
			Name: "eventhub namespace with NSP association",
			Content: `
resource "azurerm_eventhub_namespace" "example" {
}

resource "azurerm_network_security_perimeter_association" "example" {
  name        = azurerm_eventhub_namespace.example.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_eventhub_namespace.example.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple eventhub namespaces with one missing NSP association",
			Content: `
resource "azurerm_eventhub_namespace" "example1" {
}

resource "azurerm_eventhub_namespace" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  name        = azurerm_eventhub_namespace.example1.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_eventhub_namespace.example1.id
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermEventhubNamespaceNetworkSecurityPerimeterAssociation(),
					Message: "EventHub Namespace 'example2' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 5, Column: 1},
						End:      hcl.Pos{Line: 5, Column: 49},
					},
				},
			},
		},
		{
			Name: "multiple eventhub namespaces all with NSP associations",
			Content: `
resource "azurerm_eventhub_namespace" "example1" {
}

resource "azurerm_eventhub_namespace" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  name        = azurerm_eventhub_namespace.example1.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_eventhub_namespace.example1.id
}

resource "azurerm_network_security_perimeter_association" "example2" {
  name        = azurerm_eventhub_namespace.example2.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_eventhub_namespace.example2.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "eventhub namespace with count and NSP association with count",
			Content: `
resource "azurerm_eventhub_namespace" "example1" {
  count = var.test ? 1 : 0
}

resource "azurerm_network_security_perimeter_association" "example1" {
  count = var.test ? 1 : 0
  resource_id                           = azurerm_eventhub_namespace.example1[0].id
}

resource "azurerm_network_security_perimeter_association" "example2" {
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "no eventhub namespaces defined",
			Content: `
resource "azurerm_resource_group" "example" {
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermEventhubNamespaceNetworkSecurityPerimeterAssociation()

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
