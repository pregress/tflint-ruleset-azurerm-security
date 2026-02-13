# azurerm_key_vault_network_security_perimeter_association

**Severity:** Warning


## Example

```hcl
resource "azurerm_key_vault" "example" {
    # ...
}
```

## Why

Network Security Perimeter (NSP) associations provide an additional layer of network isolation and security for Azure Key Vaults. By associating a Key Vault with a Network Security Perimeter, you ensure that access to the vault is restricted to resources within the defined security perimeter, reducing the risk of unauthorized access and data breaches.

## How to Fix

```hcl
resource "azurerm_key_vault" "example" {
    # ...
}

resource "azurerm_network_security_perimeter_association" "example" {
  name        = azurerm_key_vault.example.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_key_vault.example.id
}
```


## How to disable

```hcl
rule "azurerm_key_vault_network_security_perimeter_association" {
  enabled = false
}
```
