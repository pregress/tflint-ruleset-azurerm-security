package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AzurermKeyVaultNetworkAclsDefaultDeny checks that network_acls default_action is set to "Deny"
type AzurermKeyVaultNetworkAclsDefaultDeny struct {
	tflint.DefaultRule

	resourceType string
	blockName    string
}

// NewAzurermKeyVaultNetworkAclsDefaultDeny returns a new rule instance
func NewAzurermKeyVaultNetworkAclsDefaultDeny() *AzurermKeyVaultNetworkAclsDefaultDeny {
	return &AzurermKeyVaultNetworkAclsDefaultDeny{
		resourceType: "azurerm_key_vault",
		blockName:    "network_acls",
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultNetworkAclsDefaultDeny) Name() string {
	return "azurerm_key_vault_network_acls_default_deny"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultNetworkAclsDefaultDeny) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermKeyVaultNetworkAclsDefaultDeny) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultNetworkAclsDefaultDeny) Link() string {
	return ""
}

// Check checks if network_acls default_action is set to "Deny"
func (r *AzurermKeyVaultNetworkAclsDefaultDeny) Check(runner tflint.Runner) error {
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
		networkAcls := resource.Body.Blocks

		if len(networkAcls) == 0 {
			runner.EmitIssue(
				r,
				"network_acls block is not defined, consider adding it with default_action = \"Deny\"",
				resource.DefRange,
			)
			continue
		}

		for _, networkAcl := range networkAcls {
			if networkAcl.Type != r.blockName {
				continue
			}

			attribute, exists := networkAcl.Body.Attributes["default_action"]
			if !exists {
				runner.EmitIssue(
					r,
					"default_action is not defined in network_acls block",
					networkAcl.DefRange,
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