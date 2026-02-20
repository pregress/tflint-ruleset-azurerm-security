package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermStorageAccountDefaultToOAuthAuthentication checks that default_to_oauth_authentication is enabled for azurerm_storage_account
type AzurermStorageAccountDefaultToOAuthAuthentication struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermStorageAccountDefaultToOAuthAuthentication returns a new rule instance
func NewAzurermStorageAccountDefaultToOAuthAuthentication() *AzurermStorageAccountDefaultToOAuthAuthentication {
	return &AzurermStorageAccountDefaultToOAuthAuthentication{
		resourceType:  "azurerm_storage_account",
		attributeName: "default_to_oauth_authentication",
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountDefaultToOAuthAuthentication) Name() string {
	return "azurerm_storage_account_default_to_oauth_authentication"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountDefaultToOAuthAuthentication) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountDefaultToOAuthAuthentication) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermStorageAccountDefaultToOAuthAuthentication) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if default_to_oauth_authentication is enabled for azurerm_storage_account
func (r *AzurermStorageAccountDefaultToOAuthAuthentication) Check(runner tflint.Runner) error {
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
				"default_to_oauth_authentication is not defined and should be true",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"default_to_oauth_authentication should be true",
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
