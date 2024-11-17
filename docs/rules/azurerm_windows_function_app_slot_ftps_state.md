# azurerm_windows_function_app_slot_ftps_state

**Severity:** Warning


## Example

```hcl
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
        ftps_state = "FtpsOnly"
    }
}
```

## Why

Disabling FTPS ensures that file transfer protocols are not used, reducing the risk of data interception and enhancing the overall security of Windows function app.

## How to Fix

```hcl
resource "azurerm_windows_function_app_slot" "example" {
    site_config {
        ftps_state = "Disabled"
    }
}
```


## How to disable

```hcl
rule "azurerm_windows_function_app_slot_ftps_state" {
  enabled = false
}
```

