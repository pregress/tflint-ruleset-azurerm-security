# azurerm_linux_function_app_minimum_tls_version

**Severity:** Warning


## Example

```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        minimum_tls_version = "1.0"
    }
}
```

## Why

Enforcing a minimum TLS version of 1.2 ensures secure communication by adhering to modern encryption standards, protecting data in transit from vulnerabilities in older TLS versions, as versions 1.0 and 1.1 are insecure.

## How to Fix

```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        minimum_tls_version = "1.2"
    }
}
```


## How to disable

```hcl
rule "azurerm_linux_function_app_minimum_tls_version" {
  enabled = false
}
```

