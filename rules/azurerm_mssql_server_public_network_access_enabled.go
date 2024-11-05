package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermMsSQLServerPublicNetworkAccessEnabled checks that transparent data encryption is enabled
type AzurermMsSQLServerPublicNetworkAccessEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermMsSQLServerPublicNetworkAccessEnabled returns a new rule instance
func NewAzurermMsSQLServerPublicNetworkAccessEnabled() *AzurermMsSQLServerPublicNetworkAccessEnabled {
	return &AzurermMsSQLServerPublicNetworkAccessEnabled{
		resourceType:  "azurerm_mssql_server",
		attributeName: "public_network_access_enabled",
	}
}

// Name returns the rule name
func (r *AzurermMsSQLServerPublicNetworkAccessEnabled) Name() string {
	return "azurerm_mssql_server_public_network_access_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSQLServerPublicNetworkAccessEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSQLServerPublicNetworkAccessEnabled) Severity() tflint.Severity {
	return tflint.NOTICE
}

// Link returns the rule reference link
func (r *AzurermMsSQLServerPublicNetworkAccessEnabled) Link() string {
	return ""
}

// Check checks if transparent data encryption is enabled
func (r *AzurermMsSQLServerPublicNetworkAccessEnabled) Check(runner tflint.Runner) error {
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
