package rules

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultNetworkSecurityPerimeterAssociation checks that key vaults have an NSP association
type AzurermKeyVaultNetworkSecurityPerimeterAssociation struct {
	tflint.DefaultRule

	resourceType string
}

// NewAzurermKeyVaultNetworkSecurityPerimeterAssociation returns a new rule instance
func NewAzurermKeyVaultNetworkSecurityPerimeterAssociation() *AzurermKeyVaultNetworkSecurityPerimeterAssociation {
	return &AzurermKeyVaultNetworkSecurityPerimeterAssociation{
		resourceType: "azurerm_key_vault",
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultNetworkSecurityPerimeterAssociation) Name() string {
	return "azurerm_key_vault_network_security_perimeter_association"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultNetworkSecurityPerimeterAssociation) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermKeyVaultNetworkSecurityPerimeterAssociation) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultNetworkSecurityPerimeterAssociation) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if key vaults have an associated network security perimeter
func (r *AzurermKeyVaultNetworkSecurityPerimeterAssociation) Check(runner tflint.Runner) error {
	// Get all azurerm_key_vault resources
	keyVaults, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "name"},
		},
	}, nil)
	if err != nil {
		return err
	}

	// Get all azurerm_network_security_perimeter_association resources
	nspAssociations, err := runner.GetResourceContent("azurerm_network_security_perimeter_association", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "resource_id"},
		},
	}, nil)
	if err != nil {
		return err
	}

	// Build a map of key vault resource IDs that have NSP associations
	associatedKeyVaults := make(map[string]bool)

	for _, assoc := range nspAssociations.Blocks {
		if resourceIDAttr, exists := assoc.Body.Attributes["resource_id"]; exists {
			// Check if the resource_id references a key vault
			vars := resourceIDAttr.Expr.Variables()
			for _, v := range vars {
				if len(v) >= 3 {
					if root, ok := v[0].(hcl.TraverseRoot); ok {
						if root.Name == "azurerm_key_vault" {
							if attrTraverse, ok := v[1].(hcl.TraverseAttr); ok {
								keyVaultName := attrTraverse.Name
								if idTraverse, ok := v[2].(hcl.TraverseAttr); ok {
									if idTraverse.Name == "id" {
										associatedKeyVaults[keyVaultName] = true
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Check each key vault to see if it has an NSP association
	for _, keyVault := range keyVaults.Blocks {
		keyVaultLabel := ""
		if len(keyVault.Labels) > 1 {
			keyVaultLabel = keyVault.Labels[1]
		}

		if keyVaultLabel != "" && !associatedKeyVaults[keyVaultLabel] {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Key Vault '%s' does not have an associated azurerm_network_security_perimeter_association", keyVaultLabel),
				keyVault.DefRange,
			)
		}
	}

	return nil
}
