# azurerm_iothub_endpoint_eventhub_authentication_type

**Severity:** Notice


## Example

```hcl
resource "azurerm_iothub_endpoint_eventhub" "example" {
    authentication_type = "connectionString"
}
```

## Why

Using identityBased authentication with a managed identity enhances security by avoiding hardcoded connection strings, reducing the risk of credential leakage, and leveraging Azure's identity management for secure and scalable access control.

## How to Fix

```hcl
resource "azurerm_iothub_endpoint_eventhub" "example" {
    authentication_type = "identityBased"
}
```

## How to disable

```hcl
rule "azurerm_iothub_endpoint_eventhub_authentication_type" {
  enabled = false
}
```

