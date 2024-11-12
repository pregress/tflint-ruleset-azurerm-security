// main.go
package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/rules"
)

func createRuleSet() *tflint.BuiltinRuleSet {
	return &tflint.BuiltinRuleSet{
		Name:    "azurerm-security",
		Version: "0.1.6",
		Rules: []tflint.Rule{
			rules.NewAzurermEventhubNamespacePublicNetworkAccessEnabled(),
			rules.NewAzurermEventhubNamespaceUnsecureTLS(),
			rules.NewAzurermIoTHubEndpointEventHubAuthenticationType(),
			rules.NewAzurermKeyVaultNetworkACLsDefaultDeny(),
			rules.NewAzurermKeyVaultPublicNetworkAccessEnabled(),
			rules.NewAzurermLinuxFunctionAppFtpsState(),
			rules.NewAzurermLinuxFunctionAppHTTPSOnly(),
			rules.NewAzurermLinuxFunctionAppMinimumTLSVersion(),
			rules.NewAzurermLinuxWebAppFtpsState(),
			rules.NewAzurermLinuxWebAppHTTPSOnly(),
			rules.NewAzurermLinuxWebAppMinimumTLSVersion(),
			rules.NewAzurermMssqlDatabaseEncryption(),
			rules.NewAzurermMsSQLFirewallRuleAllAllowed(),
			rules.NewAzurermMsSQLServerAdAuthOnly(),
			rules.NewAzurermMsSQLServerPublicNetworkAccessEnabled(),
			rules.NewAzurermMsSQLServerUnsecureTLS(),
			rules.NewAzurermStorageAccountHTTPSTrafficOnlyEnabled(),
			rules.NewAzurermStorageAccountPublicNetworkAccessEnabled(),
			rules.NewAzurermStorageAccountUnsecureTLS(),
			rules.NewAzurermWindowsFunctionAppFtpsState(),
			rules.NewAzurermWindowsFunctionAppHTTPSOnly(),
			rules.NewAzurermWindowsFunctionAppMinimumTLSVersion(),
			rules.NewAzurermWindowsWebAppFtpsState(),
			rules.NewAzurermWindowsWebAppHTTPSOnly(),
			rules.NewAzurermWindowsWebAppMinimumTLSVersion(),
		},
	}
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: createRuleSet(),
	})
}