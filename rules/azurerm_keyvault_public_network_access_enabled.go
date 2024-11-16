package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultPublicNetworkAccessEnabled checks that transparent data encryption is enabled
type AzurermKeyVaultPublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermKeyVaultPublicNetworkAccessEnabled returns a new rule instance
func NewAzurermKeyVaultPublicNetworkAccessEnabled() *AzurermKeyVaultPublicNetworkAccessEnabled {
	return &AzurermKeyVaultPublicNetworkAccessEnabled{
		resourceType:  "azurerm_key_vault",
		attributeName: "public_network_access_enabled",
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultPublicNetworkAccessEnabled) Name() string {
	return "azurerm_key_vault_public_network_access_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultPublicNetworkAccessEnabled) Enabled() bool {
	return false
}

// Severity returns the rule severity
func (r *AzurermKeyVaultPublicNetworkAccessEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermKeyVaultPublicNetworkAccessEnabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if transparent data encryption is enabled
func (r *AzurermKeyVaultPublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
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
				"public_network_access_enabled is not defined and defaults to true, consider disabling it",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if val {
				runner.EmitIssue(
					r,
					"Consider changing public_network_access_enabled to false",
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
