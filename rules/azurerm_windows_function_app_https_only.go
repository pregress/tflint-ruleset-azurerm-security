package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermWindowsFunctionAppHTTPSOnly checks that transparent data encryption is enabled
type AzurermWindowsFunctionAppHTTPSOnly struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermWindowsFunctionAppHTTPSOnly returns a new rule instance
func NewAzurermWindowsFunctionAppHTTPSOnly() *AzurermWindowsFunctionAppHTTPSOnly {
	return &AzurermWindowsFunctionAppHTTPSOnly{
		resourceType:  "azurerm_windows_function_app",
		attributeName: "https_only",
	}
}

// Name returns the rule name
func (r *AzurermWindowsFunctionAppHTTPSOnly) Name() string {
	return "azurerm_windows_function_app_https_only"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermWindowsFunctionAppHTTPSOnly) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermWindowsFunctionAppHTTPSOnly) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermWindowsFunctionAppHTTPSOnly) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if transparent data encryption is enabled
func (r *AzurermWindowsFunctionAppHTTPSOnly) Check(runner tflint.Runner) error {
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
