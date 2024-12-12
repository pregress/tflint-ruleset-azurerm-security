# azurerm_container_group_image_registry_credential_identity

**Severity:** Warning


## Example

```hcl
resource "azurerm_container_group" "example" {
  image_registry_credential {
    server = "example.azurecr.io"
  }
}
```

## Why

Using user_assigned_identity_id for image_registry_credential ensures secure, passwordless authentication to Azure Container Registry (ACR) via a managed identity, reducing the risk of credential exposure and enhancing access control.

## How to Fix

```hcl
resource "azurerm_container_group" "example" {
  identity{
    type = "UserAssigned"
    identity_ids = [ data.azurerm_user_assigned_identity.example.id ]
  }

  image_registry_credential {
    server = "example.azurecr.io"
    user_assigned_identity_id = data.azurerm_user_assigned_identity.example.id
  }
}
```


## How to disable

```hcl
rule "azurerm_container_group_image_registry_credential_identity" {
  enabled = false
}
```

