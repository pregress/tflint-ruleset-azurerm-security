package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermMsSqlServerPublicNetworkAccessEnabled checks that transparent data encryption is enabled
type AzurermMsSqlServerPublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermMsSqlServerPublicNetworkAccessEnabled returns a new rule instance
func NewAzurermMsSqlServerPublicNetworkAccessEnabled() *AzurermMsSqlServerPublicNetworkAccessEnabled {
	return &AzurermMsSqlServerPublicNetworkAccessEnabled{
		resourceType:  "azurerm_mssql_server",
		attributeName: "public_network_access_enabled",
	}
}

// Name returns the rule name
func (r *AzurermMsSqlServerPublicNetworkAccessEnabled) Name() string {
	return "azurerm_mssql_server_public_network_access_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSqlServerPublicNetworkAccessEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSqlServerPublicNetworkAccessEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermMsSqlServerPublicNetworkAccessEnabled) Link() string {
	return ""
}

// Check checks if transparent data encryption is enabled
func (r *AzurermMsSqlServerPublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
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
