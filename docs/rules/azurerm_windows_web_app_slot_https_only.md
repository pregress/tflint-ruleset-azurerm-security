# azurerm_windows_web_app_slot_https_only

**Severity:** Warning


## Example

```hcl
resource "azurerm_windows_web_app_slot" "example" {
    https_only = false
}
```

## Why

Enforcing https_only ensures all communications with the resource are encrypted, protecting sensitive data in transit and mitigating the risk of man-in-the-middle attacks.

## How to Fix

```hcl
resource "azurerm_windows_web_app_slot" "example" {
    https_only = true
}
```


## How to disable

```hcl
rule "azurerm_windows_web_app_slot_https_only" {
  enabled = false
}
```

