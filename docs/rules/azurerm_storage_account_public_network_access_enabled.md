# azurerm_storage_account_public_network_access_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
}
```

The rule supports both the legacy `public_network_access_enabled` (bool) property and the newer `public_network_access` property (`Disabled`, `Enabled` or `SecuredByPerimeter`, defaults to `Enabled`). No issue is reported when any of the following is true:

- `public_network_access` is set to `Disabled` or `SecuredByPerimeter`
- `public_network_access_enabled` is set to `false`
- a `network_rules` block has `default_action = "Deny"`

## Why

Storage accounts with unrestricted public network access expose your data to potential security threats. By either disabling public network access altogether or implementing network rules with "Deny" as the default action, you can significantly reduce your storage account's attack surface.

## How to Fix

Option 1: Disable public network access completely (or restrict it to a network security perimeter with `SecuredByPerimeter`):

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access = "Disabled"
}
```

With older provider versions, use the legacy property instead:

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = false
}
```

Option 2: Implement network rules with default action set to "Deny":

```hcl
resource "azurerm_storage_account" "example" {
    network_rules {
        default_action = "Deny"
        bypass         = ["AzureServices"]
        # Add specific IP rules or virtual network subnet IDs as needed
        ip_rules       = ["203.0.113.0/24"]
    }
}
```

This configuration enables fine-grained access control, allowing connectivity only from specified IP addresses or virtual networks while blocking all other traffic.

## How to disable

```hcl
rule "azurerm_storage_account_public_network_access_enabled" {
  enabled = false
}
```

