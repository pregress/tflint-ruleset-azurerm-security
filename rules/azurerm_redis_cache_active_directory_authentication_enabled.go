package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermRedisCacheAADAuhtenticationEnabled checks that active_directory_authentication_enabled is enabled for azurerm_redis_cache
type AzurermRedisCacheAADAuhtenticationEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermRedisCacheAADAuhtenticationEnabled returns a new rule instance
func NewAzurermRedisCacheAADAuhtenticationEnabled() *AzurermRedisCacheAADAuhtenticationEnabled {
	return &AzurermRedisCacheAADAuhtenticationEnabled{
		resourceType:  "azurerm_redis_cache",
		attributeName: "active_directory_authentication_enabled",
	}
}

// Name returns the rule name
func (r *AzurermRedisCacheAADAuhtenticationEnabled) Name() string {
	return "azurerm_redis_cache_active_directory_authentication_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermRedisCacheAADAuhtenticationEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermRedisCacheAADAuhtenticationEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermRedisCacheAADAuhtenticationEnabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if active_directory_authentication_enabled is enabled for azurerm_redis_cache
func (r *AzurermRedisCacheAADAuhtenticationEnabled) Check(runner tflint.Runner) error {
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
				"active_directory_authentication_enabled is not defined and should be true",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"active_directory_authentication_enabled should be true",
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
