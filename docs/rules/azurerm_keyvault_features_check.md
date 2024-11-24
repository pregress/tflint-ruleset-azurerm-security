# azurerm_keyvault_features_check

**Severity:** Warning


## Example

```hcl
provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
      recover_soft_deleted_key_vaults = false
    }
  }
}
```

## Why

Setting purge_soft_delete_on_destroy and recover_soft_deleted_key_vaults to true ensures that deleted Key Vaults are securely purged and recoverable, preventing unintended data loss while adhering to compliance and security policies.

## How to Fix

```hcl
provider "azurerm" {
  alias = "prod"
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
  }
}
```


## How to disable

```hcl
rule "azurerm_keyvault_features_check" {
  enabled = false
}
```

