# azurerm_mssql_firewall_rule_all_allowed

**Severity:** Error


## Example

```hcl
resource "azurerm_mssql_firewall_rule" "example" {
    start_ip_address = "0.0.0.0"
    end_ip_address   = "255.255.255.255"
}
```

## Why

Avoiding a firewall rule with the range 0.0.0.0 - 255.255.255.255 prevents exposing the SQL database to the entire internet, reducing the risk of unauthorized access and potential attacks.

## How to Fix

```hcl
resource "azurerm_mssql_firewall_rule" "example" {
    start_ip_address = "10.0.0.0"
    end_ip_address   = "10.0.0.255"
}
```


## How to disable

```hcl
rule "azurerm_mssql_firewall_rule_all_allowed" {
  enabled = false
}
```

