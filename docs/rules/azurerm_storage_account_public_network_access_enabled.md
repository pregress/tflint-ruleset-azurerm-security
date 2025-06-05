# azurerm_storage_account_public_network_access_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_storage_account" "example" {
    public_network_access_enabled = true
}
```

## Why

Storage accounts with unrestricted public network access expose your data to potential security threats. By either disabling public network access altogether or implementing network rules with "Deny" as the default action, you can significantly reduce your storage account's attack surface.

## How to Fix

Option 1: Disable public network access completely:

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

