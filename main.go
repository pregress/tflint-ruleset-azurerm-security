// main.go
package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/plugin"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/project"
	"github.com/terraform-linters/tflint-ruleset-azurerm-security/rules"
)

func createRuleSet() *tflint.BuiltinRuleSet {
	return &tflint.BuiltinRuleSet{
		Name:    "azurerm-security",
		Version: project.Version,
		Rules: []tflint.Rule{
			rules.NewAzurermContainerGroupImageRegistryCredentialIdentity(),
			rules.NewAzurermEventhubNamespacePublicNetworkAccessEnabled(),
			rules.NewAzurermEventhubNamespaceUnsecureTLS(),
			rules.NewAzurermIoTHubEndpointEventHubAuthenticationType(),
			rules.NewAzureRmKeyVaultFeaturesRule(),
			rules.NewAzurermKeyVaultNetworkSecurityPerimeterAssociation(),
			rules.NewAzurermKeyVaultPublicNetworkAccessEnabled(),
			rules.NewAzurermKeyVaultRbacDisabled(),
			rules.NewAzurermKeyVaultCertificateLifetimeAction(),
			rules.NewAzurermKeyVaultKeyRotationPolicy(),
			rules.NewAzurermLinuxFunctionAppFtpsState(),
			rules.NewAzurermLinuxFunctionAppHTTPSOnly(),
			rules.NewAzurermLinuxFunctionAppMinimumTLSVersion(),
			rules.NewAzurermLinuxFunctionAppScmIPRestrictionDefaultAction(),
			rules.NewAzurermLinuxFunctionAppSlotFtpsState(),
			rules.NewAzurermLinuxFunctionAppSlotHTTPSOnly(),
			rules.NewAzurermLinuxFunctionAppSlotMinimumTLSVersion(),
			rules.NewAzurermLinuxWebAppFtpsState(),
			rules.NewAzurermLinuxWebAppHTTPSOnly(),
			rules.NewAzurermLinuxWebAppMinimumTLSVersion(),
			rules.NewAzurermLinuxWebAppScmIPRestrictionDefaultAction(),
			rules.NewAzurermLinuxWebAppSlotFtpsState(),
			rules.NewAzurermLinuxWebAppSlotHTTPSOnly(),
			rules.NewAzurermLinuxWebAppSlotMinimumTLSVersion(),
			rules.NewAzurermMssqlDatabaseEncryption(),
			rules.NewAzurermMsSQLFirewallRuleAllAllowed(),
			rules.NewAzurermMsSQLServerAdAuthOnly(),
			rules.NewAzurermMsSQLServerPublicNetworkAccessEnabled(),
			rules.NewAzurermMsSQLServerUnsecureTLS(),
			rules.NewAzurermRedisCacheAADAuhtenticationEnabled(),
			rules.NewAzurermRedisCacheMinimumTLSVersion(),
			rules.NewAzurermRedisCacheNonSSLPortEnabled(),
			rules.NewAzurermStorageAccountHTTPSTrafficOnlyEnabled(),
			rules.NewAzurermStorageAccountNetworkSecurityPerimeterAssociation(),
			rules.NewAzurermStorageAccountPublicNetworkAccessEnabled(),
			rules.NewAzurermStorageAccountUnsecureTLS(),
			rules.NewAzurermWindowsFunctionAppFtpsState(),
			rules.NewAzurermWindowsFunctionAppHTTPSOnly(),
			rules.NewAzurermWindowsFunctionAppMinimumTLSVersion(),
			rules.NewAzurermWindowsFunctionAppScmIPRestrictionDefaultAction(),
			rules.NewAzurermWindowsFunctionAppSlotFtpsState(),
			rules.NewAzurermWindowsFunctionAppSlotHTTPSOnly(),
			rules.NewAzurermWindowsFunctionAppSlotMinimumTLSVersion(),
			rules.NewAzurermWindowsWebAppFtpsState(),
			rules.NewAzurermWindowsWebAppHTTPSOnly(),
			rules.NewAzurermWindowsWebAppMinimumTLSVersion(),
			rules.NewAzurermWindowsWebAppScmIPRestrictionDefaultAction(),
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
