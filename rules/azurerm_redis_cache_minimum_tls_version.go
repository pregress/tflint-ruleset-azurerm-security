package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermRedisCacheMinimumTLSVersion checks that minimum_tls_version is set to at least "1.2"
type AzurermRedisCacheMinimumTLSVersion struct {
	tflint.DefaultRule

	resourceType string
	attribute    string
	version      string
}

// NewAzurermRedisCacheMinimumTLSVersion returns a new rule instance
func NewAzurermRedisCacheMinimumTLSVersion() *AzurermRedisCacheMinimumTLSVersion {
	return &AzurermRedisCacheMinimumTLSVersion{
		resourceType: "azurerm_redis_cache",
		attribute:    "minimum_tls_version",
		version:      "1.2",
	}
}

// Name returns the rule name
func (r *AzurermRedisCacheMinimumTLSVersion) Name() string {
	return "azurerm_redis_cache_minimum_tls_version"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermRedisCacheMinimumTLSVersion) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermRedisCacheMinimumTLSVersion) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermRedisCacheMinimumTLSVersion) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that minimum_tls_version is at least "1.2"
func (r *AzurermRedisCacheMinimumTLSVersion) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.attribute},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes[r.attribute]
		if !exists {
			runner.EmitIssue(
				r,
				"minimum_tls_version is missing, should be set to 1.2 or higher",
				resource.DefRange,
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
