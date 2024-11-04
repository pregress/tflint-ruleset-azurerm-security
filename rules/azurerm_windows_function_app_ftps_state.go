package rules

import (
	"fmt"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermWindowsFunctionAppFtpsState checks that ftps_state is set to "Disabled"
type AzurermWindowsFunctionAppFtpsState struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
	expectedValue string
}

// NewAzurermWindowsFunctionAppFtpsState returns a new rule instance
func NewAzurermWindowsFunctionAppFtpsState() *AzurermWindowsFunctionAppFtpsState {
	return &AzurermWindowsFunctionAppFtpsState{
		resourceType:  "azurerm_windows_function_app",
		attributePath: []string{"site_config", "ftps_state"},
		expectedValue: "Disabled",
	}
}

// Name returns the rule name
func (r *AzurermWindowsFunctionAppFtpsState) Name() string {
	return "azurerm_windows_function_app_ftps_state"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermWindowsFunctionAppFtpsState) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermWindowsFunctionAppFtpsState) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermWindowsFunctionAppFtpsState) Link() string {
	return ""
}

// Check verifies that ftps_state is set to "Disabled"
func (r *AzurermWindowsFunctionAppFtpsState) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "site_config",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "ftps_state"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		siteConfigBlocks := resource.Body.Blocks.OfType("site_config")
		if len(siteConfigBlocks) == 0 {
			runner.EmitIssue(
				r,
				"site_config block is missing, ftps_state should be set to Disabled",
				resource.DefRange,
			)
			continue
		}

		siteConfig := siteConfigBlocks[0]
		attribute, exists := siteConfig.Body.Attributes["ftps_state"]
		if !exists {
			runner.EmitIssue(
				r,
				"ftps_state is missing in site_config, should be set to Disabled",
				siteConfig.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if !strings.EqualFold(val, r.expectedValue) {
				runner.EmitIssue(
					r,
					fmt.Sprintf("ftps_state is set to %s, should be set to Disabled", val),
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