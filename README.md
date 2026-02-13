# TFLint Ruleset AzureRm Security
[![build](https://github.com/pregress/tflint-ruleset-azurerm-securirty/actions/workflows/build.yml/badge.svg)](https://github.com/pregress/tflint-ruleset-azurerm-securirty/actions/workflows/build.yml)
[![codecov](https://codecov.io/github/pregress/tflint-ruleset-azurerm-security/graph/badge.svg?token=J3ZJ051YQQ)](https://codecov.io/github/pregress/tflint-ruleset-azurerm-security)

This is a  repository for an azurerm tflint rule set to enforce security best practices.

## Requirements

- TFLint v0.42+
- Go v1.22

## Installation

You can install the plugin with `tflint --init`. Declare a config in `.tflint.hcl` as follows:

```hcl
plugin "azurerm-security" {
  enabled = true

  version = "0.1.12"
  source  = "github.com/pregress/tflint-ruleset-azurerm-security"
}
```

## Rules

See the [documentation](docs/README.md).

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

```
plugin "azurerm-security" {
    enabled = true
}
```