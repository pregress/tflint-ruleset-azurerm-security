package rules

import (
	"fmt"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermMsSQLServerAdAuthOnly checks that azuread_authentication_only is set to true
type AzurermMsSQLServerAdAuthOnly struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
	expectedValue string
}

// NewAzurermMsSQLServerAdAuthOnly returns a new rule instance
func NewAzurermMsSQLServerAdAuthOnly() *AzurermMsSQLServerAdAuthOnly {
	return &AzurermMsSQLServerAdAuthOnly{
		resourceType:  "azurerm_mssql_server",
		attributePath: []string{"azuread_administrator", "azuread_authentication_only"},
		expectedValue: "true",
	}
}

// Name returns the rule name
func (r *AzurermMsSQLServerAdAuthOnly) Name() string {
	return "azurerm_mssql_server_azuread_authentication_only"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSQLServerAdAuthOnly) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSQLServerAdAuthOnly) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermMsSQLServerAdAuthOnly) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that azuread_authentication_only is set to "Disabled"
func (r *AzurermMsSQLServerAdAuthOnly) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "azuread_administrator",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "azuread_authentication_only"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		siteConfigBlocks := resource.Body.Blocks.OfType("azuread_administrator")
		if len(siteConfigBlocks) == 0 {
			runner.EmitIssue(
				r,
				"azuread_administrator block is missing, azuread_authentication_only should be set to true",
				resource.DefRange,
			)
			continue
		}

		siteConfig := siteConfigBlocks[0]
		attribute, exists := siteConfig.Body.Attributes["azuread_authentication_only"]
		if !exists {
			runner.EmitIssue(
				r,
				"azuread_authentication_only is missing in azuread_administrator, should be set to true",
				siteConfig.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			if !strings.EqualFold(val, r.expectedValue) {
				runner.EmitIssue(
					r,
					fmt.Sprintf("azuread_authentication_only is set to %s, should be set to true", val),
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