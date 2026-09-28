package rules

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermStorageAccountPublicNetworkAccessEnabled checks that public network access is restricted
type AzurermStorageAccountPublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType        string
	legacyAttributeName string
	attributeName       string
}

// NewAzurermStorageAccountPublicNetworkAccessEnabled returns a new rule instance
func NewAzurermStorageAccountPublicNetworkAccessEnabled() *AzurermStorageAccountPublicNetworkAccessEnabled {
	return &AzurermStorageAccountPublicNetworkAccessEnabled{
		resourceType:        "azurerm_storage_account",
		legacyAttributeName: "public_network_access_enabled",
		attributeName:       "public_network_access",
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

// Check checks if public network access is restricted
func (r *AzurermStorageAccountPublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.legacyAttributeName},
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

		var insecureRanges []hcl.Range
		secure := false

		legacyAttribute, legacyExists := resource.Body.Attributes[r.legacyAttributeName]
		if legacyExists {
			err := runner.EvaluateExpr(legacyAttribute.Expr, func(val bool) error {
				if val {
					insecureRanges = append(insecureRanges, legacyAttribute.Expr.Range())
				} else {
					secure = true
				}
				return nil
			}, nil)
			if err != nil {
				return err
			}
		}

		attribute, exists := resource.Body.Attributes[r.attributeName]
		if exists {
			err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
				if val == "Disabled" || val == "SecuredByPerimeter" {
					secure = true
				} else {
					insecureRanges = append(insecureRanges, attribute.Expr.Range())
				}
				return nil
			}, nil)
			if err != nil {
				return err
			}
		}

		// If any of the attributes is set to a secure value, the configuration is secure
		if secure {
			continue
		}

		if !legacyExists && !exists && !hasSecureNetworkRules {
			// If neither attribute exists and there are no network rules, emit an issue
			runner.EmitIssue(
				r,
				"public_network_access is not defined and defaults to Enabled, consider setting it to Disabled or SecuredByPerimeter, or adding network_rules with default_action = \"Deny\"",
				resource.DefRange,
			)
			continue
		}

		for _, rng := range insecureRanges {
			runner.EmitIssue(
				r,
				"Consider changing public_network_access to Disabled or SecuredByPerimeter (or public_network_access_enabled to false), or add network_rules with default_action = \"Deny\"",
				rng,
			)
		}
	}

	return nil
}
