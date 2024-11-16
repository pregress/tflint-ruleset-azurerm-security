package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermMssqlDatabaseEncryption checks that transparent data encryption is enabled
type AzurermMssqlDatabaseEncryption struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermMssqlDatabaseEncryption returns a new rule instance
func NewAzurermMssqlDatabaseEncryption() *AzurermMssqlDatabaseEncryption {
	return &AzurermMssqlDatabaseEncryption{
		resourceType:  "azurerm_mssql_database",
		attributeName: "transparent_data_encryption_enabled",
	}
}

// Name returns the rule name
func (r *AzurermMssqlDatabaseEncryption) Name() string {
	return "azurerm_mssql_database_encryption"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMssqlDatabaseEncryption) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMssqlDatabaseEncryption) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermMssqlDatabaseEncryption) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if transparent data encryption is enabled
func (r *AzurermMssqlDatabaseEncryption) Check(runner tflint.Runner) error {
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
				"transparent data encryption is not enabled",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"transparent data encryption must be enabled",
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
