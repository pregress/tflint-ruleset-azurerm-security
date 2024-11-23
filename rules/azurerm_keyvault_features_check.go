package rules

import (
	"fmt"
	"strings"

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
	return "azure_keyvault_features_check"
}

// Enabled returns whether the rule is enabled by default
func (r *AzureRmKeyVaultFeaturesRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzureRmKeyVaultFeaturesRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AzureRmKeyVaultFeaturesRule) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check runs the rule
func (r *AzureRmKeyVaultFeaturesRule) Check(runner tflint.Runner) error {
	// Schema for resource attributes
	resourceSchema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "provider"},
		},
	}

	resources, err := runner.GetResourceContent(r.resourceType, resourceSchema, nil)
	if err != nil {
		return err
	}

	if len(resources.Blocks) == 0 {
		return nil
	}

	// Schema for provider features
	providerSchema := &hclext.BodySchema{
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
	}

	// For each Key Vault resource
	for _, resource := range resources.Blocks {
		var providerName string

		// Check if provider is specified on the resource
		if attr, exists := resource.Body.Attributes["provider"]; exists {
			// Extract provider name from the reference (e.g., "azurerm.prod" -> "azurerm")
			providerVal, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && providerVal.Type() == cty.String {
				providerStr := providerVal.AsString()
				if strings.Contains(providerStr, ".") {
					providerName = strings.Split(providerStr, ".")[0]
				} else {
					providerName = providerStr
				}
			}
		} else {
			providerName = "azurerm"
		}

		// Get the provider configuration
		providers, err := runner.GetProviderContent(providerName, providerSchema, nil)
		if err != nil {
			return err
		}

		if len(providers.Blocks) == 0 {
			runner.EmitIssue(
				r,
				"No provider configuration found for Azure Key Vault resource",
				resource.DefRange,
			)
			continue
		}

		provider := providers.Blocks[0]

		// Check features block
		var featuresBlock *hclext.Block
		for _, block := range provider.Body.Blocks {
			if block.Type == "features" {
				featuresBlock = block
				break
			}
		}

		if featuresBlock == nil {
			runner.EmitIssue(
				r,
				fmt.Sprintf("features block is missing in the Azure provider configuration of provider %s", providerName),
				provider.DefRange,
			)
			continue
		}

		// Check key_vault block within features
		var keyVaultBlock *hclext.Block
		for _, block := range featuresBlock.Body.Blocks {
			if block.Type == "key_vault" {
				keyVaultBlock = block
				break
			}
		}

		if keyVaultBlock == nil {
			runner.EmitIssue(
				r,
				fmt.Sprintf("key_vault block is missing in the features configuration of provider %s", providerName),
				featuresBlock.DefRange,
			)
			continue
		}

		// Check purge_soft_delete_on_destroy setting
		if attr, exists := keyVaultBlock.Body.Attributes["purge_soft_delete_on_destroy"]; exists {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.Bool {
				if !val.True() {
					runner.EmitIssue(
						r,
						fmt.Sprintf("purge_soft_delete_on_destroy must be set to true in key_vault features of provider %s", providerName),
						attr.Range,
					)
				}
			}
		} else {
			runner.EmitIssue(
				r,
				fmt.Sprintf("purge_soft_delete_on_destroy must be set to true in key_vault features of provider %s", providerName),
				keyVaultBlock.DefRange,
			)
		}

		// Check recover_soft_deleted_key_vaults setting
		if attr, exists := keyVaultBlock.Body.Attributes["recover_soft_deleted_key_vaults"]; exists {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.Bool {
				if !val.True() {
					runner.EmitIssue(
						r,
						fmt.Sprintf("recover_soft_deleted_key_vaults must be set to true in key_vault features of provider %s", providerName),
						attr.Range,
					)
				}
			}
		} else {
			runner.EmitIssue(
				r,
				fmt.Sprintf("recover_soft_deleted_key_vaults must be set to true in key_vault features of provider %s", providerName),
				keyVaultBlock.DefRange,
			)
		}
	}

	return nil
}
