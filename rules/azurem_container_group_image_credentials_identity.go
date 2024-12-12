package rules

import (
	"fmt"
	"strings"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"

	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
)

// AzurermContainerGroupImageRegistryCredentialIdentity checks if ACR images have proper identity credentials
type AzurermContainerGroupImageRegistryCredentialIdentity struct {
	tflint.DefaultRule

	resourceType  string
	attributePath []string
}

// NewAzurermContainerGroupImageRegistryCredentialIdentity returns new rule
func NewAzurermContainerGroupImageRegistryCredentialIdentity() *AzurermContainerGroupImageRegistryCredentialIdentity {
	return &AzurermContainerGroupImageRegistryCredentialIdentity{
		resourceType:  "azurerm_container_group",
		attributePath: []string{"image_registry_credential", "user_assigned_identity_id"},
	}
}

// Name returns the rule name
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Name() string {
	return "azurerm_container_group_image_registry_credential_identity"
}

func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Severity() tflint.Severity {
	return tflint.WARNING
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Enabled() bool {
	return true
}

func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check runs the rule
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Check(runner tflint.Runner) error {
	resources, err := runner.GetResourceContent("azurerm_container_group", &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: "image_registry_credential",
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: "user_assigned_identity_id"},
						{Name: "server"},
					},
				},
			},
		},
	}, nil)

	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		// Check credentials
		for _, cred := range resource.Body.Blocks {
			server, exists := cred.Body.Attributes["server"]
			if !exists {
				continue
			}

			val, _ := server.Expr.Value(nil)
			serverStr := val.AsString()
			if strings.HasSuffix(serverStr, ".azurecr.io") {
				if _, exists := cred.Body.Attributes["user_assigned_identity_id"]; !exists {
					runner.EmitIssue(
						r,
						fmt.Sprintf("user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image for server %s", serverStr),
						cred.DefRange,
					)
				}
			}
		}
	}

	return nil
}
