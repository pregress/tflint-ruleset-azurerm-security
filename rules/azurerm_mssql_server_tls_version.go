package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	// "github.com/terraform-linters/tflint-ruleset-azurerm/project"
)

// AzurermMsSQLServerUnsecureTLS checks the pattern is valid
type AzurermMsSQLServerUnsecureTLS struct {
	tflint.DefaultRule

	resourceType  string
	attributeName string
	enum          []string
}

// NewAzurermMsSQLServerUnsecureTLS returns new rule with default attributes
func NewAzurermMsSQLServerUnsecureTLS() *AzurermMsSQLServerUnsecureTLS {
	return &AzurermMsSQLServerUnsecureTLS{
		resourceType:  "azurerm_mssql_server",
		attributeName: "min_tls_version",
		enum: []string{
			"TLS1_2",
			"TLS1_3",
		},
	}
}

// Name returns the rule name
func (r *AzurermMsSQLServerUnsecureTLS) Name() string {
	return "azurerm_mssql_server_unsecure_tls"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSQLServerUnsecureTLS) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSQLServerUnsecureTLS) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermMsSQLServerUnsecureTLS) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AzurermMsSQLServerUnsecureTLS) Check(runner tflint.Runner) error {
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