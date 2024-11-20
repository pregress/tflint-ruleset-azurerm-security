# azurerm_redis_cache_active_directory_authentication_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_redis_cache" "example" {
    active_directory_authentication_enabled = false
}
```

## Why

Enabling active_directory_authentication_enabled ensures secure and centralized authentication through Azure AD, reducing the reliance on shared keys and enhancing access control for the Redis Cache.

## How to Fix

```hcl
resource "azurerm_redis_cache" "example" {
    active_directory_authentication_enabled = true
}
```


## How to disable

```hcl
rule "azurerm_redis_cache_active_directory_authentication_enabled" {
  enabled = false
}
```

