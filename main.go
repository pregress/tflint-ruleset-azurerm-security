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
			rules.NewAzurermKeyVaultRbacDisabled(),
			rules.NewAzurermKeyVaultCertificateLifetimeAction(),
			rules.NewAzurermKeyVaultKeyRotationPolicy(),
			rules.NewAzurermLinuxFunctionAppFtpsState(),
			rules.NewAzurermLinuxFunctionAppHTTPSOnly(),
			rules.NewAzurermLinuxFunctionAppMinimumTLSVersion(),
			rules.NewAzurermLinuxFunctionAppSlotFtpsState(),
			rules.NewAzurermLinuxFunctionAppSlotHTTPSOnly(),
			rules.NewAzurermLinuxFunctionAppSlotMinimumTLSVersion(),
			rules.NewAzurermLinuxWebAppFtpsState(),
			rules.NewAzurermLinuxWebAppHTTPSOnly(),
			rules.NewAzurermLinuxWebAppMinimumTLSVersion(),
			rules.NewAzurermLinuxWebAppSlotFtpsState(),
			rules.NewAzurermLinuxWebAppSlotHTTPSOnly(),
			rules.NewAzurermLinuxWebAppSlotMinimumTLSVersion(),
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
			rules.NewAzurermWindowsFunctionAppSlotFtpsState(),
			rules.NewAzurermWindowsFunctionAppSlotHTTPSOnly(),
			rules.NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
			rules.NewAzurermWindowsWebAppFtpsState(),
			rules.NewAzurermWindowsWebAppHTTPSOnly(),
			rules.NewAzurermWindowsWebAppMinimumTLSVersion(),
			rules.NewAzurermWindowsWebAppSlotFtpsState(),
			rules.NewAzurermWindowsWebAppSlotHTTPSOnly(),
			rules.NewAzurermWindowsWebAppSlotMinimumTLSVersion(),
		},
	}
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: createRuleSet(),
	})
}