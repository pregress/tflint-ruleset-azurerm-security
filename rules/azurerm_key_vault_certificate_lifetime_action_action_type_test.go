package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermKeyVaultCertificateLifetimeAction(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "action_type set to invalid value",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
        lifetime_action {
            action {
                action_type = "Invalid"
            }
        }
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultCertificateLifetimeAction(),
					Message: "action_type is set to Invalid, should be set to either AutoRenew or EmailContacts",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   6,
							Column: 31,
						},
						End: hcl.Pos{
							Line:   6,
							Column: 40,
						},
					},
				},
			},
		},
		{
			Name: "action_type set to AutoRenew",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
        lifetime_action {
            action {
                action_type = "AutoRenew"
            }
        }
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "action_type set to EmailContacts",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
        lifetime_action {
            action {
                action_type = "EmailContacts"
            }
        }
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "action_type attribute missing",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
        lifetime_action {
            action {
            }
        }
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultCertificateLifetimeAction(),
					Message: "action_type is missing in action block, should be set to either AutoRenew or EmailContacts",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   5,
							Column: 13,
						},
						End: hcl.Pos{
							Line:   5,
							Column: 19,
						},
					},
				},
			},
		},
		{
			Name: "action block missing",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
        lifetime_action {
        }
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultCertificateLifetimeAction(),
					Message: "action block is missing in lifetime_action",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   4,
							Column: 9,
						},
						End: hcl.Pos{
							Line:   4,
							Column: 24,
						},
					},
				},
			},
		},
		{
			Name: "lifetime_action block missing",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultCertificateLifetimeAction(),
					Message: "lifetime_action block is missing in certificate_policy",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   3,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   3,
							Column: 23,
						},
					},
				},
			},
		},
		{
			Name: "certificate_policy block missing",
			Content: `
resource "azurerm_key_vault_certificate" "example" {
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermKeyVaultCertificateLifetimeAction(),
					Message: "certificate_policy block is missing",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 51,
						},
					},
				},
			},
		},
	}

	rule := NewAzurermKeyVaultCertificateLifetimeAction()

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