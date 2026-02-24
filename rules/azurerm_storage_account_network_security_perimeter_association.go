package rules

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermStorageAccountNetworkSecurityPerimeterAssociation checks that storage accounts have an NSP association
type AzurermStorageAccountNetworkSecurityPerimeterAssociation struct {
	tflint.DefaultRule

	resourceType string
}

// NewAzurermStorageAccountNetworkSecurityPerimeterAssociation returns a new rule instance
func NewAzurermStorageAccountNetworkSecurityPerimeterAssociation() *AzurermStorageAccountNetworkSecurityPerimeterAssociation {
	return &AzurermStorageAccountNetworkSecurityPerimeterAssociation{
		resourceType: "azurerm_storage_account",
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountNetworkSecurityPerimeterAssociation) Name() string {
	return "azurerm_storage_account_network_security_perimeter_association"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountNetworkSecurityPerimeterAssociation) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountNetworkSecurityPerimeterAssociation) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermStorageAccountNetworkSecurityPerimeterAssociation) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if storage accounts have an associated network security perimeter
func (r *AzurermStorageAccountNetworkSecurityPerimeterAssociation) Check(runner tflint.Runner) error {
	// Get all azurerm_storage_account resources
	storageAccounts, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
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

	// Build a map of storage account resource IDs that have NSP associations
	associatedStorageAccounts := make(map[string]bool)

	for _, assoc := range nspAssociations.Blocks {
		if resourceIDAttr, exists := assoc.Body.Attributes["resource_id"]; exists {
			// Check if the resource_id references a storage account
			vars := resourceIDAttr.Expr.Variables()
			for _, v := range vars {
				if len(v) >= 3 {
					if root, ok := v[0].(hcl.TraverseRoot); ok {
						if root.Name == "azurerm_storage_account" {
							if attrTraverse, ok := v[1].(hcl.TraverseAttr); ok {
								storageAccountName := attrTraverse.Name
								if len(v) == 3 {
									if idTraverse, ok := v[2].(hcl.TraverseAttr); ok && idTraverse.Name == "id" {
										associatedStorageAccounts[storageAccountName] = true
									}
								} else if len(v) == 4 {
									if _, ok := v[2].(hcl.TraverseIndex); ok {
										if idTraverse, ok := v[3].(hcl.TraverseAttr); ok && idTraverse.Name == "id" {
											associatedStorageAccounts[storageAccountName] = true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Check each storage account to see if it has an NSP association
	for _, storageAccount := range storageAccounts.Blocks {
		// Skip storage accounts with count or for_each as they may not be created
		if _, hasCount := storageAccount.Body.Attributes["count"]; hasCount {
			continue
		}
		if _, hasForEach := storageAccount.Body.Attributes["for_each"]; hasForEach {
			continue
		}

		storageAccountLabel := ""
		if len(storageAccount.Labels) > 1 {
			storageAccountLabel = storageAccount.Labels[1]
		}

		if storageAccountLabel != "" && !associatedStorageAccounts[storageAccountLabel] {
			runner.EmitIssue(
				r,
				fmt.Sprintf("Storage Account '%s' does not have an associated azurerm_network_security_perimeter_association", storageAccountLabel),
				storageAccount.DefRange,
			)
		}
	}

	return nil
}
