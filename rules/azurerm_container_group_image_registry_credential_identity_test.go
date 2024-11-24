package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AzurermContainerGroupImageRegistryCredentialIdentity(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "no warning when no ACR image is used and nog image_registry_credential block is present",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "nginx:latest"
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "no warning when no ACR image is used",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "nginx:latest"
    }
    image_registry_credential {
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "warning when ACR image is used without image_registry_credential",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "myregistry.azurecr.io/myapp:latest"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermContainerGroupImageRegistryCredentialIdentity(),
					Message: "image_registry_credential block is missing for Azure Container Registry image for server myregistry.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 45,
						},
					},
				},
			},
		},
		{
			Name: "warning when ACR image is used without user_assigned_identity_id",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "myregistry.azurecr.io/myapp:latest"
    }
    image_registry_credential {
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermContainerGroupImageRegistryCredentialIdentity(),
					Message: "user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image for server myregistry.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   7,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   7,
							Column: 30,
						},
					},
				},
			},
		},
		{
			Name: "warning when ACR image is used with credentials for wrong server",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "myregistry.azurecr.io/myapp:latest"
    }
    image_registry_credential {
        user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
		server = "otherregistry.azurecr.io"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermContainerGroupImageRegistryCredentialIdentity(),
					Message: "user_assigned_identity_id is missing in image_registry_credential for Azure Container Registry image for server myregistry.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   7,
							Column: 5,
						},
						End: hcl.Pos{
							Line:   7,
							Column: 30,
						},
					},
				},
			},
		},
		{
			Name: "no warning when ACR image is used with proper credentials",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app"
        image  = "myregistry.azurecr.io/myapp:latest"
    }
    image_registry_credential {
        user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
    }
}`,
			Expected: helper.Issues{},
		},
		{
			Name: "multiple containers with one ACR image requires credentials",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app1"
        image  = "nginx:latest"
    }
    container {
        name   = "app2"
        image  = "myregistry.azurecr.io/myapp:latest"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermContainerGroupImageRegistryCredentialIdentity(),
					Message: "image_registry_credential block is missing for Azure Container Registry image for server myregistry.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 45,
						},
					},
				},
			},
		},
		{
			Name: "multiple ACR containers with missing credential for one of them",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app1"
        image  = "myregistry1.azurecr.io/myapp1:latest"
    }
    container {
        name   = "app2"
        image  = "myregistry2.azurecr.io/myapp2:latest"
    }
    image_registry_credential {
        user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
		server = "myregistry1.azurecr.io"
    }
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAzurermContainerGroupImageRegistryCredentialIdentity(),
					Message: "image_registry_credential block is missing for Azure Container Registry image for server myregistry2.azurecr.io",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start: hcl.Pos{
							Line:   2,
							Column: 1,
						},
						End: hcl.Pos{
							Line:   2,
							Column: 45,
						},
					},
				},
			},
		},
		{
			Name: "multiple ACR containers with proper credentials",
			Content: `
resource "azurerm_container_group" "example" {
    container {
        name   = "app1"
        image  = "myregistry1.azurecr.io/myapp1:latest"
    }
    container {
        name   = "app2"
        image  = "myregistry2.azurecr.io/myapp2:latest"
    }
    image_registry_credential {
        user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
		server = "myregistry1.azurecr.io"
    }
    image_registry_credential {
        user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
		server = "myregistry2.azurecr.io"
    }
}`,
			Expected: helper.Issues{},
		},
	}

	rule := NewAzurermContainerGroupImageRegistryCredentialIdentity()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
