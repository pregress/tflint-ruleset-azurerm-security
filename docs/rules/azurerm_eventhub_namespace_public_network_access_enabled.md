# azurerm_eventhub_namespace_public_network_access_enabled

**Severity:** Notice


## Example

```hcl
resource "azurerm_eventhub_namespace" "example" {
    public_network_access_enabled = true
}
```
or 
```hcl
resource "azurerm_eventhub_namespace" "example" {
    network_rulesets {
	    default_action = "Allow"
	}
}
```

## Why

Restricting the default action to Deny or disabling public network access prevents unauthorized access to the Event Hub namespace, reducing exposure to potential threats and ensuring only trusted networks can connect.

## How to Fix

There are 2 possible solutions, disable public network access completly or use `network_rulesets` to specify specific firewall rules.

### Disbale public network access
```hcl
resource "azurerm_eventhub_namespace" "example" {
  public_network_access_enabled = true
}
```

### Use network_rulesets
```hcl
resource "azurerm_eventhub_namespace" "example" {
	network_rulesets {
	    default_action = "Deny"
	}
}
```

## How to disable

```hcl
rule "azurerm_eventhub_namespace_public_network_access_enabled" {
  enabled = false
}
```

