package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermLinuxWebAppHttpsOnly checks that transparent data encryption is enabled
type AzurermLinuxWebAppHttpsOnly struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermLinuxWebAppHttpsOnly returns a new rule instance
func NewAzurermLinuxWebAppHttpsOnly() *AzurermLinuxWebAppHttpsOnly {
	return &AzurermLinuxWebAppHttpsOnly{
		resourceType:  "azurerm_linux_web_app",
		attributeName: "https_only",
	}
}

// Name returns the rule name
func (r *AzurermLinuxWebAppHttpsOnly) Name() string {
	return "azurerm_linux_web_app_https_only"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermLinuxWebAppHttpsOnly) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermLinuxWebAppHttpsOnly) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermLinuxWebAppHttpsOnly) Link() string {
	return ""
}

// Check checks if transparent data encryption is enabled
func (r *AzurermLinuxWebAppHttpsOnly) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.attributeName},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes[r.attributeName]
		if !exists {
			// Emit an issue if the attribute does not exist
			runner.EmitIssue(
				r,
				"https_only is not defined and should be true",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"https_only should be true",
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