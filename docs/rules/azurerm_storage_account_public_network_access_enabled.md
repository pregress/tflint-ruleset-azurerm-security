# azurerm_storage_account_public_network_access_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
}
```

## Why

Disabling public_network_access_enabled ensures the Storage Account is not accessible from the public internet, reducing exposure to potential security threats and limiting access to trusted, private networks only.

## How to Fix

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = false
}
```


## How to disable

```hcl
rule "azurerm_storage_account_public_network_access_enabled" {
  enabled = false
}
```

