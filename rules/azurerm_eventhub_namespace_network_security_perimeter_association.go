package rules

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation checks that eventhub namespaces have an NSP association
type AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation struct {
	tflint.DefaultRule

	resourceType string
}

// NewAzurermEventhubNamespaceNetworkSecurityPerimeterAssociation returns a new rule instance
func NewAzurermEventhubNamespaceNetworkSecurityPerimeterAssociation() *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation {
	return &AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation{
		resourceType: "azurerm_eventhub_namespace",
	}
}

// Name returns the rule name
func (r *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation) Name() string {
	return "azurerm_eventhub_namespace_network_security_perimeter_association"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if eventhub namespaces have an associated network security perimeter
func (r *AzurermEventhubNamespaceNetworkSecurityPerimeterAssociation) Check(runner tflint.Runner) error {
	// Get all azurerm_eventhub_namespace resources
	eventhubNamespaces, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
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

	// Build a map of eventhub namespace resource IDs that have NSP associations
	associatedEventhubNamespaces := make(map[string]bool)

	for _, assoc := range nspAssociations.Blocks {
		if resourceIDAttr, exists := assoc.Body.Attributes["resource_id"]; exists {
			// Check if the resource_id references an eventhub namespace
			vars := resourceIDAttr.Expr.Variables()
			for _, v := range vars {
				if len(v) >= 3 {
					if root, ok := v[0].(hcl.TraverseRoot); ok {
						if root.Name == "azurerm_eventhub_namespace" {
							if attrTraverse, ok := v[1].(hcl.TraverseAttr); ok {
								eventhubNamespaceName := attrTraverse.Name
								if len(v) == 3 {
									if idTraverse, ok := v[2].(hcl.TraverseAttr); ok && idTraverse.Name == "id" {
										associatedEventhubNamespaces[eventhubNamespaceName] = true
									}
								} else if len(v) == 4 {
									if _, ok := v[2].(hcl.TraverseIndex); ok {
										if idTraverse, ok := v[3].(hcl.TraverseAttr); ok && idTraverse.Name == "id" {
											associatedEventhubNamespaces[eventhubNamespaceName] = true
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

	// Check each eventhub namespace to see if it has an NSP association
	for _, eventhubNamespace := range eventhubNamespaces.Blocks {
		// Skip eventhub namespaces with count or for_each as they may not be created
		if _, hasCount := eventhubNamespace.Body.Attributes["count"]; hasCount {
			continue
		}
		if _, hasForEach := eventhubNamespace.Body.Attributes["for_each"]; hasForEach {
			continue
		}

		eventhubNamespaceLabel := ""
		if len(eventhubNamespace.Labels) > 1 {
			eventhubNamespaceLabel = eventhubNamespace.Labels[1]
		}

		if eventhubNamespaceLabel != "" && !associatedEventhubNamespaces[eventhubNamespaceLabel] {
			runner.EmitIssue(
				r,
				fmt.Sprintf("EventHub Namespace '%s' does not have an associated azurerm_network_security_perimeter_association", eventhubNamespaceLabel),
				eventhubNamespace.DefRange,
			)
		}
	}

	return nil
}
