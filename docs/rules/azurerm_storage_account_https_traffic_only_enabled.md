# azurerm_storage_account_https_traffic_only_enabled

**Severity:** Warning


## Example

```hcl
resource "azurerm_storage_account" "example" {
    https_traffic_only = false
}
```

## Why

Enforcing https_traffic_only ensures all communications with the resource are encrypted, protecting sensitive data in transit and mitigating the risk of man-in-the-middle attacks.

## How to Fix

```hcl
resource "azurerm_storage_account" "example" {
    https_traffic_only = true
}
```


## How to disable

```hcl
rule "azurerm_storage_account_https_traffic_only_enabled" {
  enabled = false
}
```

