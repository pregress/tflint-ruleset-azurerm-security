package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermStorageAccountPublicNetworkAccessEnabled checks that transparent data encryption is enabled
type AzurermStorageAccountPublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermStorageAccountPublicNetworkAccessEnabled returns a new rule instance
func NewAzurermStorageAccountPublicNetworkAccessEnabled() *AzurermStorageAccountPublicNetworkAccessEnabled {
	return &AzurermStorageAccountPublicNetworkAccessEnabled{
		resourceType:  "azurerm_storage_account",
		attributeName: "public_network_access_enabled",
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Name() string {
	return "azurerm_storage_account_public_network_access_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if transparent data encryption is enabled
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.attributeName},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "network_rules",
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
		// Check for network_rules block with default_action = "Deny"
		hasSecureNetworkRulesWithDeny := false
		hasSecureNetworkRules := false
		for _, block := range resource.Body.Blocks {
			if block.Type == "network_rules" {
				hasSecureNetworkRules = true
				if defaultActionAttr, exists := block.Body.Attributes["default_action"]; exists {
					var defaultAction string
					if err := runner.EvaluateExpr(defaultActionAttr.Expr, &defaultAction, nil); err == nil {
						if defaultAction == "Deny" {
							hasSecureNetworkRulesWithDeny = true
							break
						}
					}
				}
			}
		}

		// If network rules with default_action = "Deny" exist, the configuration is secure
		if hasSecureNetworkRulesWithDeny {
			continue
		}

		attribute, exists := resource.Body.Attributes[r.attributeName]
		if !exists && !hasSecureNetworkRules {
			// If the attribute does not exist and there are no secure network rules, emit an issue
			runner.EmitIssue(
				r,
				"public_network_access_enabled is not defined and defaults to true, consider disabling it or adding network_rules with default_action = \"Deny\"",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if val {
				runner.EmitIssue(
					r,
					"Consider changing public_network_access_enabled to false or add network_rules with default_action = \"Deny\"",
					attribute.Expr.Range(),
				)
			}
			return nil
		}, nil)

		if err != nil {
			return err
		}
	}

	return nil
}
