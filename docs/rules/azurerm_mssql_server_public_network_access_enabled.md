# azurerm_mssql_server_public_network_access_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_mssql_server" "example" {
    public_network_access_enabled = true
}
```

## Why

Disabling public_network_access_enabled ensures the SQL server is not accessible from the public internet, reducing exposure to potential security threats and limiting access to trusted, private networks only.

## How to Fix

```hcl
resource "azurerm_mssql_server" "example" {
    public_network_access_enabled = false
}
```


## How to disable

```hcl
rule "azurerm_mssql_server_public_network_access_enabled" {
  enabled = false
}
```

