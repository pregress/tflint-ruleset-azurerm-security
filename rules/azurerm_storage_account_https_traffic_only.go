package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermStorageAccountHTTPSTrafficOnlyEnabled checks that https_traffic_only is enabled for azurerm_storage_account
type AzurermStorageAccountHTTPSTrafficOnlyEnabled struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
}

// NewAzurermStorageAccountHTTPSTrafficOnlyEnabled returns a new rule instance
func NewAzurermStorageAccountHTTPSTrafficOnlyEnabled() *AzurermStorageAccountHTTPSTrafficOnlyEnabled {
	return &AzurermStorageAccountHTTPSTrafficOnlyEnabled{
		resourceType:  "azurerm_storage_account",
		attributeName: "https_traffic_only",
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountHTTPSTrafficOnlyEnabled) Name() string {
	return "azurerm_storage_account_https_traffic_only_enabled"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountHTTPSTrafficOnlyEnabled) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountHTTPSTrafficOnlyEnabled) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermStorageAccountHTTPSTrafficOnlyEnabled) Link() string {
	return ""
}

// Check checks if https_traffic_only is enabled for azurerm_storage_account
func (r *AzurermStorageAccountHTTPSTrafficOnlyEnabled) Check(runner tflint.Runner) error {
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
				"https_traffic_only is not defined and should be true",
				resource.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val bool) error {
			if !val {
				runner.EmitIssue(
					r,
					"https_traffic_only should be true",
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
