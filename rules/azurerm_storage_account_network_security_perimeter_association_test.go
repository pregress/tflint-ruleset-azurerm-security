package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermStorageAccountNetworkSecurityPerimeterAssociation(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "storage account without NSP association",
			Content: `
resource "azurerm_storage_account" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountNetworkSecurityPerimeterAssociation(),
					Message: "Storage Account 'example' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 45},
					},
				},
			},
		},
		{
			Name: "storage account with NSP association",
			Content: `
resource "azurerm_storage_account" "example" {
}

resource "azurerm_network_security_perimeter_association" "example" {
  name        = azurerm_storage_account.example.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_storage_account.example.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple storage accounts with one missing NSP association",
			Content: `
resource "azurerm_storage_account" "example1" {
}

resource "azurerm_storage_account" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  name        = azurerm_storage_account.example1.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_storage_account.example1.id
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermStorageAccountNetworkSecurityPerimeterAssociation(),
					Message: "Storage Account 'example2' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 5, Column: 1},
						End:      hcl.Pos{Line: 5, Column: 46},
					},
				},
			},
		},
		{
			Name: "multiple storage accounts all with NSP associations",
			Content: `
resource "azurerm_storage_account" "example1" {
}

resource "azurerm_storage_account" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  name        = azurerm_storage_account.example1.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_storage_account.example1.id
}

resource "azurerm_network_security_perimeter_association" "example2" {
  name        = azurerm_storage_account.example2.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_storage_account.example2.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "storage account with count and NSP association with count",
			Content: `
resource "azurerm_storage_account" "example1" {
  count = var.test ? 1 : 0
}

resource "azurerm_network_security_perimeter_association" "example1" {
  count = var.test ? 1 : 0
  resource_id                           = azurerm_storage_account.example1[0].id
}

resource "azurerm_network_security_perimeter_association" "example2" {
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "no storage accounts defined",
			Content: `
resource "azurerm_resource_group" "example" {
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermStorageAccountNetworkSecurityPerimeterAssociation()

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
