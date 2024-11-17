package rules

import (
	"fmt"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermKeyVaultCertificateLifetimeAction checks that certificate_policy.lifetime_action.action.action_type
// is set to either "AutoRenew" or "EmailContacts"
type AzurermKeyVaultCertificateLifetimeAction struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
	validValues   []string
}

// NewAzurermKeyVaultCertificateLifetimeAction returns a new rule instance
func NewAzurermKeyVaultCertificateLifetimeAction() *AzurermKeyVaultCertificateLifetimeAction {
	return &AzurermKeyVaultCertificateLifetimeAction{
		resourceType:  "azurerm_key_vault_certificate",
		attributePath: []string{"certificate_policy", "lifetime_action", "action", "action_type"},
		validValues:   []string{"AutoRenew", "EmailContacts"},
	}
}

// Name returns the rule name
func (r *AzurermKeyVaultCertificateLifetimeAction) Name() string {
	return "azurerm_key_vault_certificate_lifetime_action"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermKeyVaultCertificateLifetimeAction) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermKeyVaultCertificateLifetimeAction) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermKeyVaultCertificateLifetimeAction) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that the certificate policy lifetime action is properly configured
func (r *AzurermKeyVaultCertificateLifetimeAction) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "certificate_policy",
				Body: &hclext.BodySchema{
					Blocks: []hclext.BlockSchema{
						{
							Type: "lifetime_action",
							Body: &hclext.BodySchema{
								Blocks: []hclext.BlockSchema{
									{
										Type: "action",
										Body: &hclext.BodySchema{
											Attributes: []hclext.AttributeSchema{
												{Name: "action_type"},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		certPolicyBlocks := resource.Body.Blocks.OfType("certificate_policy")
		if len(certPolicyBlocks) == 0 {
			runner.EmitIssue(
				r,
				"certificate_policy block is missing",
				resource.DefRange,
			)
			continue
		}

		certPolicy := certPolicyBlocks[0]
		lifetimeActionBlocks := certPolicy.Body.Blocks.OfType("lifetime_action")
		if len(lifetimeActionBlocks) == 0 {
			runner.EmitIssue(
				r,
				"lifetime_action block is missing in certificate_policy",
				certPolicy.DefRange,
			)
			continue
		}

		lifetimeAction := lifetimeActionBlocks[0]
		actionBlocks := lifetimeAction.Body.Blocks.OfType("action")
		if len(actionBlocks) == 0 {
			runner.EmitIssue(
				r,
				"action block is missing in lifetime_action",
				lifetimeAction.DefRange,
			)
			continue
		}

		action := actionBlocks[0]
		attribute, exists := action.Body.Attributes["action_type"]
		if !exists {
			runner.EmitIssue(
				r,
				"action_type is missing in action block, should be set to either AutoRenew or EmailContacts",
				action.DefRange,
			)
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(val string) error {
			valid := false
			for _, validValue := range r.validValues {
				if strings.EqualFold(val, validValue) {
					valid = true
					break
				}
			}
			if !valid {
				runner.EmitIssue(
					r,
					fmt.Sprintf("action_type is set to %s, should be set to either AutoRenew or EmailContacts", val),
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