package rules

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
	"github.com/zclconf/go-cty/cty"
)

// AzureRmKeyVaultFeaturesRule checks if Key Vault features are properly configured in provider
type AzureRmKeyVaultFeaturesRule struct {
	tflint.DefaultRule
	resourceType string
}

// NewAzureRmKeyVaultFeaturesRule returns a new rule
func NewAzureRmKeyVaultFeaturesRule() *AzureRmKeyVaultFeaturesRule {
	return &AzureRmKeyVaultFeaturesRule{
		resourceType: "azurerm_key_vault",
	}
}

// Name returns the rule name
func (r *AzureRmKeyVaultFeaturesRule) Name() string {
	return "azurerm_keyvault_features_check"
}

// Enabled returns whether the rule is enabled by default
func (r *AzureRmKeyVaultFeaturesRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzureRmKeyVaultFeaturesRule) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzureRmKeyVaultFeaturesRule) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check runs the rule
func (r *AzureRmKeyVaultFeaturesRule) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "provider"},
		},
	}, nil)
	if err != nil {
		return err
	}

	if len(resources.Blocks) == 0 {
		return nil
	}

	providers, err := runner.GetProviderContent("azurerm", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "alias"},
		},
		Blocks: []hclext.BlockSchema{
			{
				Type: "features",
				Body: &hclext.BodySchema{
					Blocks: []hclext.BlockSchema{
						{
							Type: "key_vault",
							Body: &hclext.BodySchema{
								Attributes: []hclext.AttributeSchema{
									{Name: "purge_soft_delete_on_destroy"},
									{Name: "recover_soft_deleted_key_vaults"},
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
		targetProvider := r.findTargetProvider(resource, providers.Blocks)
		providerDisplayName := r.getProviderDisplayName(targetProvider)

		if targetProvider == nil {
			runner.EmitIssue(
				r,
				"No provider configuration found for Azure Key Vault resource",
				resource.DefRange,
			)
			continue
		}

		// Check features block
		featuresBlock := r.findFeaturesBlock(targetProvider)
		if featuresBlock == nil {
			runner.EmitIssue(
				r,
				fmt.Sprintf("features block is missing in the Azure provider configuration of provider %s", providerDisplayName),
				targetProvider.DefRange,
			)
			continue
		}

		// Check key_vault block
		keyVaultBlock := r.findKeyVaultBlock(featuresBlock)
		if keyVaultBlock == nil {
			runner.EmitIssue(
				r,
				fmt.Sprintf("key_vault block is missing in the features configuration of provider %s", providerDisplayName),
				targetProvider.DefRange,
			)
			continue
		}

		// Check purge_soft_delete_on_destroy
		if attr, exists := keyVaultBlock.Body.Attributes["purge_soft_delete_on_destroy"]; exists {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.Bool && !val.True() {
				runner.EmitIssue(
					r,
					fmt.Sprintf("purge_soft_delete_on_destroy must be set to true in key_vault features of provider %s", providerDisplayName),
					attr.Range,
				)
			}
		}

		// Check recover_soft_deleted_key_vaults
		if attr, exists := keyVaultBlock.Body.Attributes["recover_soft_deleted_key_vaults"]; exists {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.Bool && !val.True() {
				runner.EmitIssue(
					r,
					fmt.Sprintf("recover_soft_deleted_key_vaults must be set to true in key_vault features of provider %s", providerDisplayName),
					attr.Range,
				)
			}
		}
	}

	return nil
}

func (r *AzureRmKeyVaultFeaturesRule) findTargetProvider(resource *hclext.Block, providers []*hclext.Block) *hclext.Block {
	providerAttr, hasProvider := resource.Body.Attributes["provider"]
	if !hasProvider {
		// If no provider specified, look for the default provider (no alias)
		for _, p := range providers {
			if _, hasAlias := p.Body.Attributes["alias"]; !hasAlias {
				return p
			}
		}
		return nil
	}

	// Get the raw provider reference traversal
	traversal := providerAttr.Expr.Variables()
	if len(traversal) > 0 {
		// For provider references like azurerm.prod, we expect traversal with 2 parts
		if len(traversal[0]) >= 2 {
			// The second part of the traversal should be the alias
			if aliasStep, ok := traversal[0][1].(hcl.TraverseAttr); ok {
				targetAlias := aliasStep.Name
				// Find provider with matching alias
				for _, p := range providers {
					if aliasAttr, exists := p.Body.Attributes["alias"]; exists {
						aliasVal, diags := aliasAttr.Expr.Value(nil)
						if !diags.HasErrors() && aliasVal.Type() == cty.String && aliasVal.AsString() == targetAlias {
							return p
						}
					}
				}
			}
		}
		return nil
	}

	// If we can't get the traversal, try string evaluation as fallback
	providerVal, diags := providerAttr.Expr.Value(nil)
	if !diags.HasErrors() && providerVal.Type() == cty.String {
		parts := strings.Split(providerVal.AsString(), ".")
		if len(parts) == 2 {
			targetAlias := parts[1]
			// Find provider with matching alias
			for _, p := range providers {
				if aliasAttr, exists := p.Body.Attributes["alias"]; exists {
					aliasVal, diags := aliasAttr.Expr.Value(nil)
					if !diags.HasErrors() && aliasVal.Type() == cty.String && aliasVal.AsString() == targetAlias {
						return p
					}
				}
			}
		}
	}

	return nil
}

func (r *AzureRmKeyVaultFeaturesRule) getProviderDisplayName(provider *hclext.Block) string {
	aliasAttr, hasAlias := provider.Body.Attributes["alias"]
	if !hasAlias {
		return "azurerm"
	}

	aliasVal, diags := aliasAttr.Expr.Value(nil)
	if diags.HasErrors() || aliasVal.Type() != cty.String {
		return "azurerm"
	}

	return aliasVal.AsString()
}

func (r *AzureRmKeyVaultFeaturesRule) findFeaturesBlock(provider *hclext.Block) *hclext.Block {
	for _, block := range provider.Body.Blocks {
		if block.Type == "features" {
			return block
		}
	}
	return nil
}

func (r *AzureRmKeyVaultFeaturesRule) findKeyVaultBlock(features *hclext.Block) *hclext.Block {
	for _, block := range features.Body.Blocks {
		if block.Type == "key_vault" {
			return block
		}
	}
	return nil
}
