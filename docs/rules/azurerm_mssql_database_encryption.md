# azurerm_mssql_database_encryption

**Severity:** Warning


## Example

```hcl
resource "azurerm_mssql_database" "example" {
    transparent_data_encryption_enabled = false
}
```

## Why

Enabling transparent data encryption (TDE) ensures that data at rest is encrypted, protecting sensitive information from unauthorized access in the event of a data breach or physical media theft.

## How to Fix

```hcl
resource "azurerm_mssql_database" "example" {
    transparent_data_encryption_enabled = true
}
```


## How to disable

```hcl
rule "azurerm_mssql_database_encryption" {
  enabled = false
}
```

