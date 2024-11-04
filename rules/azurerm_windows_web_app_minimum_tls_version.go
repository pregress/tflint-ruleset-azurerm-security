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
	attributePath []string
	version       string
}

// NewAzurermWindowsWebAppMinimumTlsVersion returns a new rule instance
func NewAzurermWindowsWebAppMinimumTlsVersion() *AzurermWindowsWebAppMinimumTlsVersion {
	return &AzurermWindowsWebAppMinimumTlsVersion{
		resourceType:  "azurerm_windows_web_app",
		attributePath: []string{"site_config", "minimum_tls_version"},
		version:       "1.2",
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
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermWindowsWebAppMinimumTlsVersion) Link() string {
	return ""
}

// Check verifies that minimum_tls_version is at least "1.2"
func (r *AzurermWindowsWebAppMinimumTlsVersion) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "site_config",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "minimum_tls_version"},
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
				"site_config block is missing, minimum_tls_version should be set to 1.2 or higher",
				resource.DefRange,
			)
			continue
		}

		siteConfig := siteConfigBlocks[0]
		attribute, exists := siteConfig.Body.Attributes["minimum_tls_version"]
		if !exists {
			runner.EmitIssue(
				r,
				"minimum_tls_version is missing in site_config, should be set to 1.2 or higher",
				siteConfig.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if val != r.version {
				runner.EmitIssue(
					r,
					fmt.Sprintf("minimum_tls_version is set to %s, should be %s or higher", val, r.version),
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