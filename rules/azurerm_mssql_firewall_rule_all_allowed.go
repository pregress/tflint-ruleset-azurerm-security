package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermMsSQLFirewallRuleAllAllowed checks if the firewall rule allows all IP addresses
type AzurermMsSQLFirewallRuleAllAllowed struct {
	tflint.DefaultRule

	resourceType string
	startIPAttr  string
	endIPAttr    string
}

// NewAzurermMsSQLFirewallRuleAllAllowed returns a new rule instance
func NewAzurermMsSQLFirewallRuleAllAllowed() *AzurermMsSQLFirewallRuleAllAllowed {
	return &AzurermMsSQLFirewallRuleAllAllowed{
		resourceType: "azurerm_mssql_firewall_rule",
		startIPAttr:  "start_ip_address",
		endIPAttr:    "end_ip_address",
	}
}

// Name returns the rule name
func (r *AzurermMsSQLFirewallRuleAllAllowed) Name() string {
	return "azurerm_mssql_firewall_rule_all_allowed"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermMsSQLFirewallRuleAllAllowed) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermMsSQLFirewallRuleAllAllowed) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AzurermMsSQLFirewallRuleAllAllowed) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks if the firewall rule allows all IP addresses
func (r *AzurermMsSQLFirewallRuleAllAllowed) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: r.startIPAttr},
			{Name: r.endIPAttr},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		startIP, exists := resource.Body.Attributes[r.startIPAttr]
		if !exists {
			continue
		}

		endIP, exists := resource.Body.Attributes[r.endIPAttr]
		if !exists {
			continue
		}

		var startIPValue, endIPValue string
		err := runner.EvaluateExpr(startIP.Expr, func(val string) error {
			startIPValue = val
			return nil
		}, nil)
		if err != nil {
			return err
		}

		err = runner.EvaluateExpr(endIP.Expr, func(val string) error {
			endIPValue = val
			return nil
		}, nil)
		if err != nil {
			return err
		}

		if startIPValue == "0.0.0.0" && endIPValue == "255.255.255.255" {
			runner.EmitIssue(
				r,
				"Firewall rule allows access from all IP addresses (0.0.0.0-255.255.255.255). Consider restricting the IP range for better security.",
				resource.DefRange,
			)
		}
	}

	return nil
}