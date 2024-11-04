// main.go
package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/rules"
)

func CreateRuleSet() *tflint.BuiltinRuleSet {
	return &tflint.BuiltinRuleSet{
		Name:    "azurerm-security",
		Version: "0.1.2",
		Rules: []tflint.Rule{
			rules.NewAzurermKeyVaultPublicNetworkAccessEnabled(),
			rules.NewAzurermLinuxWebAppFtpsState(),
			rules.NewAzurermLinuxWebAppHttpsOnly(),
			rules.NewAzurermLinuxWebAppMinimumTlsVersion(),
			rules.NewAzurermMssqlDatabaseEncryption(),
			rules.NewAzurermStorageAccountPublicNetworkAccessEnabled(),
			rules.NewAzurermStorageAccountUnsecureTls(),
			rules.NewAzurermWindowsWebAppFtpsState(),
			rules.NewAzurermWindowsWebAppHttpsOnly(),
			rules.NewAzurermWindowsWebAppMinimumTlsVersion(),
		},
	}
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: CreateRuleSet(),
	})
}