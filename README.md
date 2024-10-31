# TFLint Ruleset AzureRm Security
[![build](https://github.com/pregress/tflint-ruleset-azurerm-securirty/actions/workflows/build.yml/badge.svg)](https://github.com/pregress/tflint-ruleset-azurerm-securirty/actions/workflows/build.yml)

This is a  repository for an azurerm tflint rule set to enforce security best practices.

## Requirements

- TFLint v0.42+
- Go v1.22

## Installation

You can install the plugin with `tflint --init`. Declare a config in `.tflint.hcl` as follows:

```hcl
plugin "azurerm-security" {
  enabled = true

  version = "0.1.2"
  source  = "github.com/pregress/tflint-ruleset-azurerm-security"
}
```

## Rules

|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_linux_web_app_ftps_state|Disable sftp to a linux web app |ERROR|✔||
|azurerm_linux_web_app_minimum_tls_version|Enforce TLS 1.2 on linux web apps |ERROR|✔||
|azurerm_mssql_database_transparent_data_encryption_enabled|Enforce transparant data encryption|ERROR|✔||
|azurerm_storage_account_tls_version|Enforce TLS 1.2 on storage accounts |ERROR|✔||
|azurerm_windows_web_app_ftps_state|Disable sftp to a windows web app |ERROR|✔||
|azurerm_windows_web_app_minimum_tls_version|Enforce TLS 1.2 on windows web apps |ERROR|✔||

## Building the plugin

Clone the repository locally and run the following command:

```
$ make
```

You can easily install the built plugin with the following:

```
$ make install
```

Note that if you install the plugin with make install, you must omit the version and source attributes in .tflint.hcl:

plugin "azurerm-security" {
    enabled = true
}