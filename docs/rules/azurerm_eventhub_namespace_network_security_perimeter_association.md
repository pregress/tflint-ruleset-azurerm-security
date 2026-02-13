# azurerm_eventhub_namespace_network_security_perimeter_association

**Severity:** Warning


## Example

```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-eventhub-namespace"
  location            = "West Europe"
  resource_group_name = "example-rg"
  sku                 = "Standard"
  capacity            = 1
}
```

## Why

Network Security Perimeter (NSP) associations provide an additional layer of network isolation and security for Azure EventHub Namespaces. By associating an EventHub Namespace with a Network Security Perimeter, you ensure that access to the namespace is restricted to resources within the defined security perimeter, reducing the risk of unauthorized access and data breaches.

## How to Fix

```hcl
resource "azurerm_eventhub_namespace" "example" {
  name                = "example-eventhub-namespace"
  location            = "West Europe"
  resource_group_name = "example-rg"
  sku                 = "Standard"
  capacity            = 1
}

resource "azurerm_network_security_perimeter_association" "example" {
  name        = azurerm_eventhub_namespace.example.name
  access_mode = "Enforced"

  network_security_perimeter_profile_id = azurerm_network_security_perimeter_profile.example.id
  resource_id                           = azurerm_eventhub_namespace.example.id
}
```


## How to disable

```hcl
rule "azurerm_eventhub_namespace_network_security_perimeter_association" {
  enabled = false
}
```
