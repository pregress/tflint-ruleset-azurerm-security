package rules

import (
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermContainerGroupImageRegistryCredentialIdentity checks that user_assigned_identity_id is set when connecting to a azure container registry
type AzurermContainerGroupImageRegistryCredentialIdentity struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
}

// NewAzurermContainerGroupImageRegistryCredentialIdentity returns a new rule instance
func NewAzurermContainerGroupImageRegistryCredentialIdentity() *AzurermContainerGroupImageRegistryCredentialIdentity {
	return &AzurermContainerGroupImageRegistryCredentialIdentity{
		resourceType:  "azurerm_container_group",
		attributePath: []string{"image_registry_credential", "user_assigned_identity_id"},
	}
}

// Name returns the rule name
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Name() string {
	return "azurerm_container_group_user_assigned_identity_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check verifies that user_assigned_identity_id is set when connecting to a azure container registry
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "container",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "image"},
					},
				},
			},
			{
				Type: "image_registry_credential",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "user_assigned_identity_id"},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		// First check if any container uses Azure Container Registry
		containerBlocks := resource.Body.Blocks.OfType("container")
		hasAzureContainerRegistry := false

		for _, container := range containerBlocks {
			if imageAttr, exists := container.Body.Attributes["image"]; exists {
				var imageValue string
				err := runner.EvaluateExpr(imageAttr.Expr, &imageValue, nil)
				if err != nil {
					continue
				}

				if strings.Contains(imageValue, "azurecr.io/") {
					hasAzureContainerRegistry = true
					break
				}
			}
		}

		// TODO: the server should match the credential block

		// Only proceed with checks if Azure Container Registry is used
		if !hasAzureContainerRegistry {
			continue
		}

		imageRegistryCredentialBlocks := resource.Body.Blocks.OfType("image_registry_credential")
		if len(imageRegistryCredentialBlocks) == 0 {
			runner.EmitIssue(
				r,
				"image_registry_credential block is missing for Azure Container Registry image",
				resource.DefRange,
			)
			continue
		}

		siteConfig := imageRegistryCredentialBlocks[0]
		_, exists := siteConfig.Body.Attributes["user_assigned_identity_id"]
		if !exists {
			runner.EmitIssue(
				r,
				"user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image",
				siteConfig.DefRange,
			)
			continue
		}
	}

	return nil
}
