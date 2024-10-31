package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermWindowsWebAppMinimumTlsVersion checks that minimum_tls_version is set to at least "1.2"
type AzurermWindowsWebAppMinimumTlsVersion struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	version    string
}

// NewAzurermWindowsWebAppMinimumTlsVersion returns a new rule instance
func NewAzurermWindowsWebAppMinimumTlsVersion() *AzurermWindowsWebAppMinimumTlsVersion {
	return &AzurermWindowsWebAppMinimumTlsVersion{
		resourceType:  "azurerm_windows_web_app",
		attributeName: "minimum_tls_version",
		version:    "1.2",
	}
}

// Name returns the rule name
func (r *AzurermWindowsWebAppMinimumTlsVersion) Name() string {
	return "azurerm_windows_web_app_minimum_tls_version"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermWindowsWebAppMinimumTlsVersion) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermWindowsWebAppMinimumTlsVersion) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AzurermWindowsWebAppMinimumTlsVersion) Link() string {
	return ""
}

// Check verifies that minimum_tls_version is at least "1.2"
func (r *AzurermWindowsWebAppMinimumTlsVersion) Check(runner tflint.Runner) error {
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
			// Emit issue if minimum_tls_version attribute is missing
			runner.EmitIssue(
				r,
				fmt.Sprintf("%s is missing, should be set to %s or higher", r.attributeName, r.version),
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if val != r.version {
				runner.EmitIssue(
					r,
					fmt.Sprintf("%s is set to %s, should be %s or higher", r.attributeName, val, r.version),
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
