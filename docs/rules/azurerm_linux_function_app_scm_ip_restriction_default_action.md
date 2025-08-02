# azurerm_linux_function_app_scm_ip_restriction_default_action

**Severity:** Warning


## Example

```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        scm_ip_restriction_default_action = "Allow"
    }
}
```
or 
```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        # Missing scm_ip_restriction_default_action (defaults to Allow)
    }
}
```

## Why

Setting the `scm_ip_restriction_default_action` to "Deny" prevents unauthorized access to the Source Control Manager (SCM) interface, reducing exposure to potential threats and ensuring only trusted networks can connect to the deployment and management endpoints.

## How to Fix

Set the `scm_ip_restriction_default_action` to "Deny" and configure specific `scm_ip_restriction` rules to allow legitimate access.

### Using service tag
```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        scm_ip_restriction_default_action = "Deny"
        
        scm_ip_restriction {
            service_tag = "AzureDevOps"
            name        = "Allow Azure DevOps"
            priority    = 100
            action      = "Allow"
        }
    }
}
```

### Using IP range
```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        scm_ip_restriction_default_action = "Deny"
        
        scm_ip_restriction {
            ip_address = "203.0.113.0/24"
            name       = "Corporate Network"
            priority   = 100
            action     = "Allow"
        }
    }
}
```


## How to disable

```hcl
rule "azurerm_linux_function_app_scm_ip_restriction_default_action" {
  enabled = false
}
```

