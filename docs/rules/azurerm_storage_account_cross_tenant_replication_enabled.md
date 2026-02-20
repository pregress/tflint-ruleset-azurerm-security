# azurerm_storage_account_cross_tenant_replication_enabled

**Severity:** Warning


## Example

```hcl
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageaccount"
  resource_group_name      = "example-rg"
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
```

## Why

Cross-tenant replication should be disabled to prevent data from being replicated to storage accounts in other Azure AD tenants. This reduces the risk of unauthorized data access and helps maintain data sovereignty by ensuring your data stays within your organization's tenant boundary.

## How to Fix

```hcl
resource "azurerm_storage_account" "example" {
  name                              = "examplestorageaccount"
  resource_group_name               = "example-rg"
  location                          = "West Europe"
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  cross_tenant_replication_enabled  = false
}
```


## How to disable

```hcl
rule "azurerm_storage_account_cross_tenant_replication_enabled" {
  enabled = false
}
```
