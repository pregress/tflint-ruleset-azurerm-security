package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermLinuxWebAppFtpsState checks if ftps_state is disabled
type AzurermLinuxWebAppFtpsState struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	expectedValue string
}

// NewAzurermLinuxWebAppFtpsState creates a new rule instance
func NewAzurermLinuxWebAppFtpsState() *AzurermLinuxWebAppFtpsState {
	return &AzurermLinuxWebAppFtpsState{
		resourceType:  "azurerm_linux_web_app",
		attributeName: "ftps_state",
		expectedValue: "Disabled",
	}
}

// Name returns the rule name
func (r *AzurermLinuxWebAppFtpsState) Name() string {
	return "azurerm_linux_web_app_ftps_state"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermLinuxWebAppFtpsState) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermLinuxWebAppFtpsState) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AzurermLinuxWebAppFtpsState) Link() string {
	return ""
}

// Check verifies that ftps_state is set to "Disabled"
func (r *AzurermLinuxWebAppFtpsState) Check(runner tflint.Runner) error {
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
			runner.EmitIssue(
				r,
				"ftps_state should be set to Disabled",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if val != r.expectedValue {
				runner.EmitIssue(
					r,
					fmt.Sprintf("ftps_state is set to %q, should be Disabled", val),
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