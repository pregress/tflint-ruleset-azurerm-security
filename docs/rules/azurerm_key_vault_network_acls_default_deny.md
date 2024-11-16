# azurerm_key_vault_network_acls_default_deny

**Severity:** Warning


## Example

```hcl
resource "azurerm_key_vault" "example" {
    network_acls {
        default_action = "Allow"
    }
}
```

## Why

Setting default_action to Deny ensures that the Azure Key Vault is not accessible from unauthorized or untrusted networks, improving security by restricting access to explicitly allowed sources only.

## How to Fix

```hcl
resource "azurerm_key_vault" "example" {
    network_acls {
        default_action = "Deny"
    }
}
```


## How to disable

```hcl
rule "azurerm_key_vault_network_acls_default_deny" {
  enabled = false
}
```

