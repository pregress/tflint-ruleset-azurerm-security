package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultNetworkSecurityPerimeterAssociation(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "key vault without NSP association",
			Content: `
resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkSecurityPerimeterAssociation(),
					Message: "Key Vault 'example' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 2, Column: 1},
						End:      hcl.Pos{Line: 2, Column: 39},
					},
				},
			},
		},
		{
			Name: "key vault with NSP association",
			Content: `
resource "azurerm_key_vault" "example" {
}

resource "azurerm_network_security_perimeter_association" "example" {
  resource_id                           = azurerm_key_vault.example.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple key vaults with one missing NSP association",
			Content: `
resource "azurerm_key_vault" "example1" {
}

resource "azurerm_key_vault" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  resource_id                           = azurerm_key_vault.example1.id
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkSecurityPerimeterAssociation(),
					Message: "Key Vault 'example2' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 5, Column: 1},
						End:      hcl.Pos{Line: 5, Column: 40},
					},
				},
			},
		},
		{
			Name: "multiple key vaults all with NSP associations",
			Content: `
resource "azurerm_key_vault" "example1" {
}

resource "azurerm_key_vault" "example2" {
}

resource "azurerm_network_security_perimeter_association" "example1" {
  resource_id                           = azurerm_key_vault.example1.id
}

resource "azurerm_network_security_perimeter_association" "example2" {
  resource_id                           = azurerm_key_vault.example2.id
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "keyvault with count and NSP association with count",
			Content: `
resource "azurerm_key_vault" "example1" {
  count = var.test ? 1 : 0
}

resource "azurerm_network_security_perimeter_association" "example1" {
  count = var.test ? 1 : 0
  resource_id                           = azurerm_key_vault.example1[0].id
}`,
			Expected: helper.Issues{},
		},

		{
			Name: "keyvault with count and NSP association with count",
			Content: `
resource "azurerm_key_vault" "example1" {
  count = var.test ? 1 : 0
}

resource "azurerm_key_vault" "example2" {
  count = 1
}

resource "azurerm_network_security_perimeter_association" "example1" {
  count = var.test ? 1 : 0
  resource_id                           = azurerm_key_vault.example1[0].id
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultNetworkSecurityPerimeterAssociation(),
					Message: "Key Vault 'example2' does not have an associated azurerm_network_security_perimeter_association",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 6, Column: 1},
						End:      hcl.Pos{Line: 6, Column: 40},
					},
				},
			},
		},
		{
			Name: "no key vaults defined",
			Content: `
resource "azurerm_resource_group" "example" {
  name     = "example-rg"
  location = "West Europe"
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermKeyVaultNetworkSecurityPerimeterAssociation()

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
