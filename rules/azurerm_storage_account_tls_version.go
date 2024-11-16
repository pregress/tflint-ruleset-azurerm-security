package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
	
)

// AzurermStorageAccountUnsecureTLS checks the pattern is valid
type AzurermStorageAccountUnsecureTLS struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	enum          []string
}

// NewAzurermStorageAccountUnsecureTLS returns new rule with default attributes
func NewAzurermStorageAccountUnsecureTLS() *AzurermStorageAccountUnsecureTLS {
	return &AzurermStorageAccountUnsecureTLS{
		resourceType:  "azurerm_storage_account",
		attributeName: "min_tls_version",
		enum: []string{
			"TLS1_2",
			"TLS1_3",
		},
	}
}

// Name returns the rule name
func (r *AzurermStorageAccountUnsecureTLS) Name() string {
	return "azurerm_storage_account_unsecure_tls"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermStorageAccountUnsecureTLS) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermStorageAccountUnsecureTLS) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermStorageAccountUnsecureTLS) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks the pattern is valid
func (r *AzurermStorageAccountUnsecureTLS) Check(runner tflint.Runner) error {
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