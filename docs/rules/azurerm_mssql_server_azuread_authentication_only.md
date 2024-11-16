# azurerm_mssql_server_azuread_authentication_only

**Severity:** Warning


## Example

```hcl
resource "azurerm_mssql_server" "example" {
    azuread_administrator {
        azuread_authentication_only = false
    }
}
```

## Why

Enabling azuread_authentication_only ensures that only Azure AD identities can authenticate to the SQL server, providing enhanced security through centralized identity management and eliminating the risks associated with SQL authentication credentials.

## How to Fix

```hcl
resource "azurerm_mssql_server" "example" {
    azuread_administrator {
        azuread_authentication_only  = true
    }
}
```


## How to disable

```hcl
rule "azurerm_mssql_server_azuread_authentication_only" {
  enabled = false
}
```

