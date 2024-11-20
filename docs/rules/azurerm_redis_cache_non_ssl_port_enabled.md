# azurerm_redis_cache_non_ssl_port_enabled

**Severity:** Warning


## Example

```hcl
resource "azurerm_redis_cache" "example" {
    non_ssl_port_enabled = true
}
```

## Why

Disabling non_ssl_port_enabled ensures all connections to the Redis Cache are encrypted, protecting sensitive data in transit from interception or tampering.

## How to Fix

```hcl
resource "azurerm_redis_cache" "example" {
    non_ssl_port_enabled = false
}
```


## How to disable

```hcl
rule "azurerm_redis_cache_non_ssl_port_enabled" {
  enabled = false
}
```

