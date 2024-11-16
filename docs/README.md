# Rules

## azurerm_eventhub_namespace
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_eventhub_namespace_public_network_access_enabled](./rules/azurerm_eventhub_namespace_public_network_access_enabled.md)|Consider disabling public network access on eventhubs. |NOTICE|✔|
|[azurerm_eventhub_namespace_minimum_tls_version](./rules/azurerm_eventhub_namespace_unsecure_tls.md)|Enforce TLS 1.2 on event hubs |WARNING|✔|

## azurerm_iothub_endpoint_eventhub
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_iothub_endpoint_eventhub_authentication_type](./rules/azurerm_iothub_endpoint_eventhub_authentication_type.md)|Consider using managed identity to authenticate agains eventhub. |NOTICE||

## azurerm_key_vault
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_key_vault_public_network_access_enabled](./rules/azurerm_key_vault_public_network_access_enabled.md)|Consider disabling public network access on keyvaults. |NOTICE||
|[azurerm_key_vault_network_acls_default_deny](./rules/azurerm_key_vault_network_acls_default_deny.md)|Deny network access to Keyvaults. You can add `bypass = "AzureServices"` to allow azure services to connect to keyvault or add `ip_rules`|WARNING|✔|

## azurerm_linux_function_app
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_linux_function_app_ftps_state](./rules/azurerm_linux_function_app_ftps_state.md)|Disable sftp to a linux function app |WARNING|✔|
|[azurerm_linux_function_app_https_only](./rules/azurerm_linux_function_app_https_only.md)|Force all traffic over https |WARNING|✔|
|[azurerm_linux_function_app_minimum_tls_version](./rules/azurerm_linux_function_app_minimum_tls_version.md)|Enforce TLS 1.2 on linux function apps |WARNING|✔|

## azurerm_linux_web_app
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_linux_web_app_ftps_state](./rules/azurerm_linux_web_app_ftps_state.md)|Disable sftp to a linux web app |WARNING|✔|
|[azurerm_linux_web_app_https_only](./rules/azurerm_linux_web_app_https_only.md)|Force all traffic over https |WARNING|✔|
|[azurerm_linux_web_app_minimum_tls_version](./rules/azurerm_linux_web_app_minimum_tls_version.md)|Enforce TLS 1.2 on linux web apps |WARNING|✔|

## azurerm_mssql_database
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_mssql_database_transparent_data_encryption_enabled](./rules/azurerm_mssql_database_encryption.md)|Enforce transparant data encryption|WARNING|✔|

## azurerm_mssql_server
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_mssql_server_azuread_authentication_only](./rules/azurerm_mssql_server_azuread_authentication_only.md)|Only user Azure AD authentication to SQL |WARNING|✔|
|[azurerm_mssql_server_public_network_access_enabled](./rules/azurerm_mssql_server_public_network_access_enabled.md)|Consider disabling public network access on SQL servers. |NOTICE|✔|
|[azurerm_mssql_server_minimum_tls_version](./rules/azurerm_mssql_server_unsecure_tls.md)|Enforce TLS 1.2 on SQL servers. |WARNING|✔|

## azurerm_mssql_firewall_rule

|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_mssql_firewall_rule_all_allowed](./rules/azurerm_mssql_firewall_rule_all_allowed.md)|Remove a firewall rule that allows any ip.|ERROR|✔|


## azurerm_storage_account
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_storage_account_https_traffic_only_enabled](./rules/azurerm_storage_account_https_traffic_only_enabled.md)|Enforce all traffic to use https on storage accounts|WARNING|✔|
|[azurerm_storage_account_public_network_access_enabled](./rules/azurerm_storage_account_public_network_access_enabled.md)|Consider disabling public network access on storage accounts. |NOTICE|✔|
|[azurerm_storage_account_tls_version](./rules/azurerm_storage_account_unsecure_tls.md)|Enforce TLS 1.2 on storage accounts |WARNING|✔|

## azurerm_windows_function_app
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_windows_function_app_ftps_state](./rules/azurerm_windows_function_app_ftps_state.md)|Disable sftp to a windows function app |WARNING|✔|
|[azurerm_windows_function_app_https_only](./rules/azurerm_windows_function_app_https_only.md)|Force all traffic over https |WARNING|✔|
|[azurerm_windows_function_app_minimum_tls_version](./rules/azurerm_windows_function_app_minimum_tls_version.md)|Enforce TLS 1.2 on windows function apps |WARNING|✔|


## azurerm_windows_web_app
|Name|Description|Severity|Enabled|
| --- | --- | --- | --- |
|[azurerm_windows_web_app_ftps_state](./rules/azurerm_windows_web_app_ftps_state.md)|Disable sftp to a windows web app |WARNING|✔|
|[azurerm_windows_web_app_https_only](./rules/azurerm_windows_web_app_https_only.)|Force all traffic over https |WARNING|✔|
|[azurerm_windows_web_app_minimum_tls_version](./rules/azurerm_windows_web_app_minimum_tls_version.md)|Enforce TLS 1.2 on windows web apps |WARNING|✔|
