package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/rules"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: &tflint.BuiltinRuleSet{
			Name:    "azurerm-security",
			Version: "0.1.0",
			Rules: []tflint.Rule{
				rules.NewAzurermStorageAccountUnsecureTls(),
			},
		},
	})
}