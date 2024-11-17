# azurerm_key_vault_key_rotation_policy

**Severity:** Warning


## Example

```hcl
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
      # mising expire_after
    }
}
```

## Why

Defining a rotation_policy with expire_after ensures that keys are rotated regularly, minimizing the risk of key compromise and maintaining compliance with security best practices.

## How to Fix

```hcl
resource "azurerm_key_vault_key" "example" {
    rotation_policy {
        expire_after = "P90D"
    }
}
```


## How to disable

```hcl
rule "azurerm_key_vault_key_rotation_policy" {
  enabled = false
}
```

