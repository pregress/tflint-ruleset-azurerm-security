package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultNetworkACLsDefaultDeny checks that network_acls default_action is set to "Deny"
type AzurermKeyVaultNetworkACLsDefaultDeny struct {
	tflint.DefaultRule

	resourceType string
	blockName    string
}

// NewAzurermKeyVaultNetworkACLsDefaultDeny returns a new rule instance
func NewAzurermKeyVaultNetworkACLsDefaultDeny() *AzurermKeyVaultNetworkACLsDefaultDeny {
	return &AzurermKeyVaultNetworkACLsDefaultDeny{
		resourceType: "azurerm_key_vault",
		blockName:    "network_acls",
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultNetworkACLsDefaultDeny) Name() string {
	return "azurerm_key_vault_network_acls_default_deny"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultNetworkACLsDefaultDeny) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermKeyVaultNetworkACLsDefaultDeny) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultNetworkACLsDefaultDeny) Link() string {	
	return project.ReferenceLink(r.Name())
}

// Check checks if network_acls default_action is set to "Deny"
func (r *AzurermKeyVaultNetworkACLsDefaultDeny) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: r.blockName,
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "default_action"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		networkACLs := resource.Body.Blocks

		if len(networkACLs) == 0 {
			runner.EmitIssue(
				r,
				"network_acls block is not defined, consider adding it with default_action = \"Deny\"",
				resource.DefRange,
			)
			continue
		}

		for _, networkACL := range networkACLs {
			if networkACL.Type != r.blockName {
				continue
			}

			attribute, exists := networkACL.Body.Attributes["default_action"]
			if !exists {
				runner.EmitIssue(
					r,
					"default_action is not defined in network_acls block",
					networkACL.DefRange,
				)
				continue
			}

			err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
				if val != "Deny" {
					runner.EmitIssue(
						r,
						"network_acls default_action should be set to \"Deny\"",
						attribute.Expr.Range(),
					)
				}
				return nil
			}, nil)

			if err != nil {
				return err
			}
		}
	}

	return nil
}