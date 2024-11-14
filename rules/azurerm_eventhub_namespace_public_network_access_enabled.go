package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermEventhubNamespacePublicNetworkAccessEnabled checks that transparent data encryption is enabled
type AzurermEventhubNamespacePublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermEventhubNamespacePublicNetworkAccessEnabled returns a new rule instance
func NewAzurermEventhubNamespacePublicNetworkAccessEnabled() *AzurermEventhubNamespacePublicNetworkAccessEnabled {
	return &AzurermEventhubNamespacePublicNetworkAccessEnabled{
		resourceType:  "azurerm_eventhub_namespace",
		attributeName: "public_network_access_enabled",
	}
}

// Name returns the rule name
func (r *AzurermEventhubNamespacePublicNetworkAccessEnabled) Name() string {
	return "azurerm_eventhub_namespace_public_network_access_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermEventhubNamespacePublicNetworkAccessEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermEventhubNamespacePublicNetworkAccessEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermEventhubNamespacePublicNetworkAccessEnabled) Link() string {
	return ""
}

// Check checks if transparent data encryption is enabled
func (r *AzurermEventhubNamespacePublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.attributeName},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "network_rulesets",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "default_action"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		// Check if the `public_network_access_enabled` attribute exists and its value
		attribute, exists := resource.Body.Attributes[r.attributeName]
		publicNetworkEnabled := false
		if !exists {
			publicNetworkEnabled = true
		} else {
			if err := runner.EvaluateExpr(attribute.Expr, &publicNetworkEnabled, nil); err != nil {
				return err
			}
	
			if !publicNetworkEnabled {
				return nil
			}
		}

		// Check network_rulesets block when `public_network_access_enabled` is true
		if publicNetworkEnabled {
			issueEmitted := false
			for _, block := range resource.Body.Blocks {
				if block.Type == "network_rulesets" {
					actionAttr, exists := block.Body.Attributes["default_action"]
					if exists {
						var defaultAction string
						if err := runner.EvaluateExpr(actionAttr.Expr, &defaultAction, nil); err != nil {
							return err
						}
						if defaultAction == "Allow" {
							runner.EmitIssue(
								r,
								"public_network_access_enabled is true and network_rulesets block with default_action = Allow, Consider changing the default_action to deny",
								actionAttr.Expr.Range(),
							)
							issueEmitted = true
						} else {
							return nil
						}
					}
				}
			}

			if !issueEmitted {
				runner.EmitIssue(
					r,
					"public_network_access_enabled is not defined and defaults to true, consider disabling it or add network_rulesets block with default_action = Deny",
					resource.DefRange,
				)
				continue
			}
		}

		
	}

	return nil
}
