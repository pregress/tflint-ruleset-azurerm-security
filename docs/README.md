# Rules

## azurerm_eventhub_namespace
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_eventhub_namespace_public_network_access_enabled|Consider disabling public network access on eventhubs. |NOTICE|✔||
|azurerm_eventhub_namespace_minimum_tls_version|Enforce TLS 1.2 on event hubs |WARNING|✔||

## azurerm_key_vault
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_key_vault_public_network_access_enabled|Consider disabling public network access on keyvaults. |NOTICE|✔||

## azurerm_linux_function_app
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_linux_function_app_ftps_state|Disable sftp to a linux function app |WARNING|✔||
|azurerm_linux_function_app_https_only|Force all traffic over https |WARNING|✔||
|azurerm_linux_function_app_minimum_tls_version|Enforce TLS 1.2 on linux function apps |WARNING|✔||

## azurerm_linux_web_app
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_linux_web_app_ftps_state|Disable sftp to a linux web app |WARNING|✔||
|azurerm_linux_web_app_https_only|Force all traffic over https |WARNING|✔||
|azurerm_linux_web_app_minimum_tls_version|Enforce TLS 1.2 on linux web apps |WARNING|✔||

## azurerm_mssql_database
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_mssql_database_transparent_data_encryption_enabled|Enforce transparant data encryption|WARNING|✔||

## azurerm_mssql_server
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_mssql_server_azuread_authentication_only |Only user Azure AD authentication to SQL |WARNING|✔||
|azurerm_mssql_server_public_network_access_enabled|Consider disabling public network access on SQL servers. |NOTICE|✔||
|azurerm_mssql_server_minimum_tls_version|Enforce TLS 1.2 on SQL servers. |WARNING|✔||

## azurerm_mssql_firewall_rule

|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_mssql_firewall_rule_all_allowed|Remove a firewall rule that allows the any ip.|ERROR|✔||


## azurerm_storage_account
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_storage_account_public_network_access_enabled|Consider disabling public network access on storage accounts. |NOTICE|✔||
|azurerm_storage_account_tls_version|Enforce TLS 1.2 on storage accounts |WARNING|✔||

## azurerm_windows_function_app
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_windows_function_app_ftps_state|Disable sftp to a windows function app |WARNING|✔||
|azurerm_windows_function_app_https_only|Force all traffic over https |WARNING|✔||
|azurerm_windows_function_app_minimum_tls_version|Enforce TLS 1.2 on windows function apps |WARNING|✔||


## azurerm_windows_web_app
|Name|Description|Severity|Enabled|Link|
| --- | --- | --- | --- | --- |
|azurerm_windows_web_app_ftps_state|Disable sftp to a windows web app |WARNING|✔||
|azurerm_windows_web_app_https_only|Force all traffic over https |WARNING|✔||
|azurerm_windows_web_app_minimum_tls_version|Enforce TLS 1.2 on windows web apps |WARNING|✔||