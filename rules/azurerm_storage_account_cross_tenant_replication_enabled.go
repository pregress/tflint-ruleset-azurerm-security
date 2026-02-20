package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermStorageAccountCrossTenantReplicationEnabled checks that cross_tenant_replication_enabled is disabled for azurerm_storage_account
type AzurermStorageAccountCrossTenantReplicationEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermStorageAccountCrossTenantReplicationEnabled returns a new rule instance
func NewAzurermStorageAccountCrossTenantReplicationEnabled() *AzurermStorageAccountCrossTenantReplicationEnabled {
	return &AzurermStorageAccountCrossTenantReplicationEnabled{
		resourceType:  "azurerm_storage_account",
		attributeName: "cross_tenant_replication_enabled",
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountCrossTenantReplicationEnabled) Name() string {
	return "azurerm_storage_account_cross_tenant_replication_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountCrossTenantReplicationEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountCrossTenantReplicationEnabled) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermStorageAccountCrossTenantReplicationEnabled) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if cross_tenant_replication_enabled is disabled for azurerm_storage_account
func (r *AzurermStorageAccountCrossTenantReplicationEnabled) Check(runner tflint.Runner) error {
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
			// Emit an issue if the attribute does not exist (defaults to false)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if val {
				runner.EmitIssue(
					r,
					"cross_tenant_replication_enabled should be false",
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
