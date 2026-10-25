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

## Scope

The rule checks the `features` block of the `provider "azurerm"` blocks declared in the same module. A Key Vault whose provider is not declared there is not reported, because a reusable module gets its provider from its caller (an inherited default provider, or an alias passed in with `configuration_aliases`). Run the rule on the module that declares the provider.

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

