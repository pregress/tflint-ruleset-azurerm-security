package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermWindowsFunctionAppScmIPRestrictionDefaultAction checks that scm_ip_restriction_default_action is set to "Deny"
type AzurermWindowsFunctionAppScmIPRestrictionDefaultAction struct {
	tflint.DefaultRule

	resourceType string
}

// NewAzurermWindowsFunctionAppScmIPRestrictionDefaultAction returns a new rule instance
func NewAzurermWindowsFunctionAppScmIPRestrictionDefaultAction() *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction {
	return &AzurermWindowsFunctionAppScmIPRestrictionDefaultAction{
		resourceType: "azurerm_windows_function_app",
	}
}

// Name returns the rule name
func (r *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction) Name() string {
	return "azurerm_windows_function_app_scm_ip_restriction_default_action"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that scm_ip_restriction_default_action is set to "Deny"
func (r *AzurermWindowsFunctionAppScmIPRestrictionDefaultAction) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "site_config",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "scm_ip_restriction_default_action"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		// Check if site_config block exists
		hasSiteConfig := false
		for _, block := range resource.Body.Blocks {
			if block.Type == "site_config" {
				hasSiteConfig = true

				// Check if scm_ip_restriction_default_action attribute exists
				if attr, exists := block.Body.Attributes["scm_ip_restriction_default_action"]; exists {
					err := runner.EvaluateExpr(attr.Expr, func(val string) error {
						if val != "Deny" {
							runner.EmitIssue(
								r,
								"scm_ip_restriction_default_action should be Deny",
								attr.Expr.Range(),
							)
						}
						return nil
					}, nil)
					if err != nil {
						return err
					}
				} else {
					// Attribute is missing in site_config block
					runner.EmitIssue(
						r,
						"scm_ip_restriction_default_action is not defined and should be Deny",
						resource.DefRange,
					)
				}
				break
			}
		}

		// If site_config block doesn't exist
		if !hasSiteConfig {
			runner.EmitIssue(
				r,
				"scm_ip_restriction_default_action is not defined and should be Deny",
				resource.DefRange,
			)
		}
	}

	return nil
}
