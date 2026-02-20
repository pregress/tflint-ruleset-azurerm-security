# azurerm_storage_account_default_to_oauth_authentication

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

Default to Azure Active Directory authorization in the Azure portal when accessing the Storage Account instead of access keys. This enhances security by using identity-based authentication, which provides better audit trails, supports conditional access policies, and eliminates the need to manage and rotate access keys.

## How to Fix

```hcl
resource "azurerm_storage_account" "example" {
  name                            = "examplestorageaccount"
  resource_group_name             = "example-rg"
  location                        = "West Europe"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  default_to_oauth_authentication = true
}
```


## How to disable

```hcl
rule "azurerm_storage_account_default_to_oauth_authentication" {
  enabled = false
}
```
