# azurerm_key_vault_enable_rbac_authorization

**Severity:** Warning


## Example

```hcl
resource "azurerm_key_vault" "example" {
    enable_rbac_authorization = false
}
```

## Why

Enabling enable_rbac_authorization allows access to the Key Vault to be managed through Azure Role-Based Access Control (RBAC), providing granular, centralized, and scalable permissions management. This is considered the current best practice.

## How to Fix

```hcl
resource "azurerm_key_vault" "example" {
    enable_rbac_authorization = true
}
```


## How to disable

```hcl
rule "azurerm_key_vault_enable_rbac_authorization" {
  enabled = false
}
```

