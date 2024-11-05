package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	// "github.com/terraform-linters/tflint-ruleset-azurerm/project"
)

// AzurermMsSqlServerUnsecureTLS checks the pattern is valid
type AzurermMsSqlServerUnsecureTLS struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	enum          []string
}

// NewAzurermMsSqlServerUnsecureTLS returns new rule with default attributes
func NewAzurermMsSqlServerUnsecureTLS() *AzurermMsSqlServerUnsecureTLS {
	return &AzurermMsSqlServerUnsecureTLS{
		resourceType:  "azurerm_mssql_server",
		attributeName: "min_tls_version",
		enum: []string{
			"TLS1_2",
			"TLS1_3",
		},
	}
}

// Name returns the rule name
func (r *AzurermMsSqlServerUnsecureTLS) Name() string {
	return "azurerm_mssql_server_unsecure_tls"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSqlServerUnsecureTLS) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSqlServerUnsecureTLS) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermMsSqlServerUnsecureTLS) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AzurermMsSqlServerUnsecureTLS) Check(runner tflint.Runner) error {
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