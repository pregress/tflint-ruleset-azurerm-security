# azurerm_key_vault_certificate_lifetime_action

**Severity:** Warning


## Example

```hcl
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
      # missing lifetime_policy 
    }
}
```

## Why

Setting lifetime_action to AutoRenew or EmailContacts ensures proactive management of certificate expiration, reducing the risk of service interruptions or security vulnerabilities caused by expired certificates.

## How to Fix

```hcl
resource "azurerm_key_vault_certificate" "example" {
    certificate_policy {
      lifetime_action {
        action {
          action_type = "AutoRenew"
        }
      }
    }
}
```


## How to disable

```hcl
rule "azurerm_key_vault_certificate_lifetime_action" {
  enabled = false
}
```

