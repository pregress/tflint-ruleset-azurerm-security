# azurerm_linux_function_app_ftps_state

**Severity:** Warning


## Example

```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        ftps_state = "FtpsOnly"
    }
}
```

## Why

Disabling FTPS ensures that file transfer protocols are not used, reducing the risk of data interception and enhancing the overall security of the Linux Function App.

## How to Fix

```hcl
resource "azurerm_linux_function_app" "example" {
    site_config {
        ftps_state = "Disabled"
    }
}
```


## How to disable

```hcl
rule "azurerm_linux_function_app_ftps_state" {
  enabled = false
}
```

