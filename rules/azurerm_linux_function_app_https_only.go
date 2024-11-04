package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermLinuxFunctionAppHttpsOnly checks that transparent data encryption is enabled
type AzurermLinuxFunctionAppHttpsOnly struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermLinuxFunctionAppHttpsOnly returns a new rule instance
func NewAzurermLinuxFunctionAppHttpsOnly() *AzurermLinuxFunctionAppHttpsOnly {
	return &AzurermLinuxFunctionAppHttpsOnly{
		resourceType:  "azurerm_linux_function_app",
		attributeName: "https_only",
	}
}

// Name returns the rule name
func (r *AzurermLinuxFunctionAppHttpsOnly) Name() string {
	return "azurerm_linux_function_app_https_only"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermLinuxFunctionAppHttpsOnly) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermLinuxFunctionAppHttpsOnly) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermLinuxFunctionAppHttpsOnly) Link() string {
	return ""
}

// Check checks if transparent data encryption is enabled
func (r *AzurermLinuxFunctionAppHttpsOnly) Check(runner tflint.Runner) error {
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
