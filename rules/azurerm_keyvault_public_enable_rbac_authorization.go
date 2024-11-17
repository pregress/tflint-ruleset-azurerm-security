package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultRbacDisabled checks that transparent data encryption is enabled
type AzurermKeyVaultRbacDisabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermKeyVaultRbacDisabled returns a new rule instance
func NewAzurermKeyVaultRbacDisabled() *AzurermKeyVaultRbacDisabled {
	return &AzurermKeyVaultRbacDisabled{
		resourceType:  "azurerm_key_vault",
		attributeName: "enable_rbac_authorization",
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultRbacDisabled) Name() string {
	return "azurerm_key_vault_enable_rbac_authorization"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultRbacDisabled) Enabled() bool {
	return false
}

// Severity returns the rule severity
func (r *AzurermKeyVaultRbacDisabled) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultRbacDisabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if transparent data encryption is enabled
func (r *AzurermKeyVaultRbacDisabled) Check(runner tflint.Runner) error {
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
				"enable_rbac_authorization is not defined and defaults to false, consider enabling it",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"Consider changing enable_rbac_authorization to true",
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
