package rules

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
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

// Severity returns the rule severity
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Severity() tflint.Severity {
	return tflint.WARNING
}

// Enabled returns whether the rule is enabled by default
func (r *AzurermContainerGroupImageRegistryCredentialIdentity) Enabled() bool {
	return true
}

// Link returns the rule reference link
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
		for _, cred := range resource.Body.Blocks {
			server, exists := cred.Body.Attributes["server"]
			if !exists {
				continue
			}

			val, diags := server.Expr.Value(nil)
			isAzureCR := false

			if diags.HasErrors() || val.IsNull() {
				// If we can't evaluate the server value directly (e.g., it's a reference),
				// check if it's referencing an Azure Container Registry
				serverExpr := server.Expr.Variables()
				for _, v := range serverExpr {
					if len(v) > 0 {
						if root, ok := v[0].(hcl.TraverseRoot); ok {
							if strings.Contains(root.Name, "azurerm_container_registry") {
								isAzureCR = true
								break
							}
						}
					}
				}
			} else {
				// For literal string values
				serverStr := val.AsString()
				isAzureCR = strings.HasSuffix(serverStr, ".azurecr.io")
				if isAzureCR {
					if _, exists := cred.Body.Attributes["user_assigned_identity_id"]; !exists {
						runner.EmitIssue(
							r,
							fmt.Sprintf("user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image for server %s", serverStr),
							cred.DefRange,
						)
						continue
					}
				}
				continue
			}

			// For references (not literal values)
			if isAzureCR {
				if _, exists := cred.Body.Attributes["user_assigned_identity_id"]; !exists {
					runner.EmitIssue(
						r,
						"user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image",
						cred.DefRange,
					)
				}
			}
		}
	}

	return nil
}
