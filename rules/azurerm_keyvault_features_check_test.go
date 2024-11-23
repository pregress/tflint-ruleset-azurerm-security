package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzureRmKeyVaultFeaturesRule(t *testing.T) {
	cases := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "no key vault resource",
			Content: `
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
  }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "default provider with correct configuration",
			Content: `
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "named provider with correct configuration",
			Content: `
provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

resource "azurerm_key_vault" "example" {
  provider = azurerm.prod
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "default provider missing features block",
			Content: `
provider "azurerm" {
}

resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "features block is missing in the Azure provider configuration of provider azurerm",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 19,
						},
					},
				},
			},
		},
		{
			Name: "named provider missing features block",
			Content: `
provider "azurerm" {
  alias = "prod"
}

resource "azurerm_key_vault" "example" {
  provider = azurerm.prod
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "features block is missing in the Azure provider configuration of provider prod",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 43,
						},
					},
				},
			},
		},
		{
			Name: "default provider missing key_vault block",
			Content: `
provider "azurerm" {
  features {}
}

resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "key_vault block is missing in the features configuration of provider azurerm",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 3,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 11,
						},
					},
				},
			},
		},
		{
			Name: "named provider missing key_vault block",
			Content: `
provider "azurerm" {
  alias = "prod"
  features {}
}

resource "azurerm_key_vault" "example" {
  provider = azurerm.prod
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "key_vault block is missing in the features configuration of provider prod",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 43,
						},
					},
				},
			},
		},
		{
			Name: "default provider with incorrect purge_soft_delete_on_destroy",
			Content: `
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "purge_soft_delete_on_destroy must be set to true in key_vault features of provider azurerm",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   5,
							Column: 7,
						},
						End: hcl.Pos{
							Line:   5,
							Column: 43,
						},
					},
				},
			},
		},
		{
			Name: "named provider with incorrect purge_soft_delete_on_destroy",
			Content: `
provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

resource "azurerm_key_vault" "example" {
  provider = azurerm.prod
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "purge_soft_delete_on_destroy must be set to true in key_vault features of provider prod",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 43,
						},
					},
				},
			},
		},
		{
			Name: "default provider with incorrect recover_soft_deleted_key_vaults",
			Content: `
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = false
    }
  }
}

resource "azurerm_key_vault" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "recover_soft_deleted_key_vaults must be set to true in key_vault features of provider azurerm",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   6,
							Column: 7,
						},
						End: hcl.Pos{
							Line:   6,
							Column: 46,
						},
					},
				},
			},
		},
		{
			Name: "named provider with incorrect recover_soft_deleted_key_vaults",
			Content: `
provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = false
    }
  }
}

resource "azurerm_key_vault" "example" {
  provider = azurerm.prod
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "recover_soft_deleted_key_vaults must be set to true in key_vault features of provider prod",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   12,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   12,
							Column: 39,
						},
					},
				},
			},
		},
		{
			Name: "multiple providers with mixed configurations",
			Content: `
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

resource "azurerm_key_vault" "example1" {
}

resource "azurerm_key_vault" "example2" {
  provider  = azurerm.prod
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzureRmKeyVaultFeaturesRule(),
					Message: "purge_soft_delete_on_destroy must be set to true in key_vault features of provider prod",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   5,
							Column: 7,
						},
						End: hcl.Pos{
							Line:   5,
							Column: 43,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{
				"resource.tf": tc.Content,
			})

			rule := NewAzureRmKeyVaultFeaturesRule()
			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, tc.Expected, runner.Issues)
		})
	}
}
