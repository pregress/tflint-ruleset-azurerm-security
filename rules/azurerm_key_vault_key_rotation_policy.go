package rules

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultKeyRotationPolicy checks that key has a rotation_policy block with expire_after set
type AzurermKeyVaultKeyRotationPolicy struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
}

// NewAzurermKeyVaultKeyRotationPolicy returns a new rule instance
func NewAzurermKeyVaultKeyRotationPolicy() *AzurermKeyVaultKeyRotationPolicy {
	return &AzurermKeyVaultKeyRotationPolicy{
		resourceType:  "azurerm_key_vault_key",
		attributePath: []string{"rotation_policy", "expire_after"},
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultKeyRotationPolicy) Name() string {
	return "azurerm_key_vault_key_rotation_policy"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultKeyRotationPolicy) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermKeyVaultKeyRotationPolicy) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultKeyRotationPolicy) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that the key has a rotation_policy block with expire_after set
func (r *AzurermKeyVaultKeyRotationPolicy) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "rotation_policy",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "expire_after"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		rotationPolicyBlocks := resource.Body.Blocks.OfType("rotation_policy")
		if len(rotationPolicyBlocks) == 0 {
			runner.EmitIssue(
				r,
				"rotation_policy block is missing, should be defined with expire_after property",
				resource.DefRange,
			)
			continue
		}

		rotationPolicy := rotationPolicyBlocks[0]
		attribute, exists := rotationPolicy.Body.Attributes["expire_after"]
		if !exists {
			runner.EmitIssue(
				r,
				"expire_after is missing in rotation_policy block",
				rotationPolicy.DefRange,
			)
			continue
		}

		// We don't validate the value of expire_after as it can be any valid duration string
		// The provider will validate the format ("P90D", "P6M", etc.)
		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			return nil
		}, nil)
		if err != nil {
			return err
		}
	}

	return nil
}