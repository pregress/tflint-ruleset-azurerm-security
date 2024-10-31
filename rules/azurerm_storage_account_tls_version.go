package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	// "github.com/terraform-linters/tflint-ruleset-azurerm/project"
)

// AzurermStorageAccountUnsecureTls checks the pattern is valid
type AzurermStorageAccountUnsecureTls struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	enum          []string
}

// NewAzurermStorageAccountUnsecureTls returns new rule with default attributes
func NewAzurermStorageAccountUnsecureTls() *AzurermStorageAccountUnsecureTls {
	return &AzurermStorageAccountUnsecureTls{
		resourceType:  "azurerm_storage_account",
		attributeName: "min_tls_version",
		enum: []string{
			"TLS1_2",
			"TLS1_3",
		},
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountUnsecureTls) Name() string {
	return "azurerm_storage_account_unsecure_tls"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountUnsecureTls) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountUnsecureTls) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AzurermStorageAccountUnsecureTls) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AzurermStorageAccountUnsecureTls) Check(runner tflint.Runner) error {
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
			continue
		}
		err := runner.EvaluateExpr(attribute.Expr, func (val string) error {
			found := false
			for _, item := range r.enum {
				if item == val {
					found = true
				}
			}
			if !found {
				runner.EmitIssue(
					r,
					fmt.Sprintf(`"%s" is an insecure value as min_tls_version`, val),
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