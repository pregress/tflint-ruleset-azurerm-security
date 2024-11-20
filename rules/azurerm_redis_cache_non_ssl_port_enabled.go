package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermRedisCacheNonSSLPortEnabled checks that non_ssl_port_enabled is enabled for azurerm_redis_cache
type AzurermRedisCacheNonSSLPortEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermRedisCacheNonSSLPortEnabled returns a new rule instance
func NewAzurermRedisCacheNonSSLPortEnabled() *AzurermRedisCacheNonSSLPortEnabled {
	return &AzurermRedisCacheNonSSLPortEnabled{
		resourceType:  "azurerm_redis_cache",
		attributeName: "non_ssl_port_enabled",
	}
}

// Name returns the rule name
func (r *AzurermRedisCacheNonSSLPortEnabled) Name() string {
	return "azurerm_redis_cache_non_ssl_port_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermRedisCacheNonSSLPortEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermRedisCacheNonSSLPortEnabled) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermRedisCacheNonSSLPortEnabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if non_ssl_port_enabled is enabled for azurerm_redis_cache
func (r *AzurermRedisCacheNonSSLPortEnabled) Check(runner tflint.Runner) error {
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
				"non_ssl_port_enabled is not defined and should be false",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if val {
				runner.EmitIssue(
					r,
					"non_ssl_port_enabled should be false",
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
