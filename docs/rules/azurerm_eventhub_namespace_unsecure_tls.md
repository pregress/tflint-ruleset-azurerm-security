# azurerm_eventhub_namespace_unsecure_tls

**Severity:** Warning


## Example

```hcl
resource "azurerm_eventhub_namespace" "example" {
    min_tls_version = "TLS1_0"
}
```

## Why

Enforcing a minimum TLS version of 1.2 ensures secure communication by adhering to modern encryption standards, protecting data in transit from vulnerabilities in older TLS versions, as versions 1.0 and 1.1 are insecure.

## How to Fix

Set the `min_tls_version` to `TLS1_2`

```hcl
resource "azurerm_eventhub_namespace" "example" {
    min_tls_version = "TLS1_2"
}
```


## How to disable

```hcl
rule "azurerm_eventhub_namespace_unsecure_tls" {
  enabled = false
}
```
