###############################################################################
# OPTION 3 – CIS Azure Security Benchmark v2.0 Gap Fixtures
#
# Each block fails a specific CIS control. The control ID, section title, and
# remediation are documented inline. Deploy with Defender for Cloud or
# Azure Policy Initiative "CIS Microsoft Azure Foundations Benchmark" to
# validate your compliance scanning pipeline.
#
# CIS Section mapping:
#   1.x  – Identity and Access Management
#   2.x  – Microsoft Defender for Cloud
#   3.x  – Storage Accounts
#   4.x  – Database Services
#   5.x  – Logging and Monitoring
#   6.x  – Networking
#   7.x  – Virtual Machines
#   8.x  – App Service
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" { features {} }

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "cis" {
  name     = "cis-benchmark-gaps-rg"
  location = "eastus2"
}

###############################################################################
# CIS 3.1  – Ensure that 'Secure transfer required' is set to 'Enabled'
# CIS 3.3  – Ensure that 'Public access level' is set to Private for blob containers
# CIS 3.7  – Ensure that 'Minimum TLS version' is set to 'TLS 1.2'
# CIS 3.8  – Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'
# CIS 3.10 – Ensure trusted Microsoft Services can access storage accounts
# CIS 3.15 – Ensure Storage logging is enabled for Queue service
###############################################################################
resource "azurerm_storage_account" "cis_3" {
  name                     = "cisbenchgap3001"
  resource_group_name      = azurerm_resource_group.cis.name
  location                 = azurerm_resource_group.cis.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # FAILS CIS 3.1 – secure transfer should be true
  enable_https_traffic_only = false

  # FAILS CIS 3.7 – should be TLS1_2
  min_tls_version = "TLS1_1"

  # FAILS CIS 3.8 – should be false
  allow_nested_items_to_be_public = true

  # FAILS CIS 3.10 – network_rules.bypass should include "AzureServices"
  network_rules {
    default_action = "Allow"  # FAILS – should be "Deny"
    bypass         = ["None"] # FAILS – missing "AzureServices", "Logging", "Metrics"
  }

  # FAILS CIS 3.15 – no queue_properties logging block
}

# FAILS CIS 3.3 – container access type should be "private"
resource "azurerm_storage_container" "cis_3" {
  name                  = "appdata"
  storage_account_name  = azurerm_storage_account.cis_3.name
  container_access_type = "container"
}

###############################################################################
# CIS 4.1.1 – Ensure 'Auditing' is set to 'On' for SQL Server
# CIS 4.1.2 – Ensure 'Auditing' Retention is 'greater than 90 days'
# CIS 4.1.3 – Ensure 'Advanced Data Security' is set to 'On' on SQL Server
# CIS 4.1.4 – Ensure Defender for SQL is 'On' for critical SQL servers
# CIS 4.1.5 – Ensure VAs send scan reports to admins/owners
# CIS 4.2.1 – Ensure SSL connection is set to 'Enabled' for PostgreSQL
# CIS 4.3.7 – Ensure 'Allow access to Azure services' for MySQL is disabled
###############################################################################
resource "azurerm_mssql_server" "cis_4" {
  name                         = "cis-sql-gap-001"
  resource_group_name          = azurerm_resource_group.cis.name
  location                     = azurerm_resource_group.cis.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "LabOnly-NotReal-99!"

  # FAILS CIS 4.1.1 – public access enabled
  public_network_access_enabled = true

  # FAILS CIS 4.1.x – minimum TLS should be 1.2
  minimum_tls_version = "1.0"

  # FAILS CIS 4.1.x – Azure AD admin not set
  # azuread_administrator block omitted
}

# FAILS CIS 4.1.1 / 4.1.2 – no azurerm_mssql_server_extended_auditing_policy
# resource "azurerm_mssql_server_extended_auditing_policy" omitted

# FAILS CIS 4.1.3 / 4.1.4 – no azurerm_mssql_server_security_alert_policy
# resource "azurerm_mssql_server_security_alert_policy" omitted

# FAILS CIS 4.1.5 – no azurerm_mssql_server_vulnerability_assessment
# resource "azurerm_mssql_server_vulnerability_assessment" omitted

resource "azurerm_postgresql_flexible_server" "cis_4" {
  name                = "cis-pg-gap-001"
  resource_group_name = azurerm_resource_group.cis.name
  location            = azurerm_resource_group.cis.location
  version             = "14"
  administrator_login    = "pgadmin"
  administrator_password = "LabOnly-NotReal-99!"
  storage_mb             = 32768
  sku_name               = "B_Standard_B1ms"

  # FAILS CIS 4.2.1 – ssl_enforcement_enabled should be true
  # (In Flexible Server this is always on, but the equivalent check
  #  is that ssl_minimal_tls_version_enforced = "TLS1_2")
  # ssl_minimal_tls_version_enforced omitted → defaults to TLS1_0

  # FAILS – backup_retention_days below 7 (CIS recommends >= 7)
  backup_retention_days        = 3
  geo_redundant_backup_enabled = false
}

###############################################################################
# CIS 5.1.1  – Ensure Diagnostic Setting captures all categories
# CIS 5.1.2  – Ensure Diagnostic Setting retains logs for 1+ year
# CIS 5.1.3  – Ensure Audit Profile captures all activities
# CIS 5.2.1  – Ensure activity log alert for 'Create Policy Assignment'
# CIS 5.2.2  – Ensure activity log alert for 'Delete Policy Assignment'
# CIS 5.2.3  – Ensure activity log alert for NSG Create/Update
# CIS 5.2.9  – Ensure activity log alert for 'Delete Security Solution'
# CIS 5.3    – Ensure logs are integrated with a SIEM (Log Analytics)
###############################################################################
resource "azurerm_log_analytics_workspace" "cis_5" {
  name                = "cis-law-gap"
  location            = azurerm_resource_group.cis.location
  resource_group_name = azurerm_resource_group.cis.name
  sku                 = "PerGB2018"
  # FAILS CIS 5.1.2 – retention should be >= 365 days
  retention_in_days = 30
}

# FAILS CIS 5.1.1 – no azurerm_monitor_diagnostic_setting on subscription
# FAILS CIS 5.2.1 through 5.2.9 – no azurerm_monitor_activity_log_alert resources
# Below is ONE alert present (5.2.1), but 5.2.2–5.2.9 are intentionally absent

resource "azurerm_monitor_action_group" "cis_5" {
  name                = "cis-ag"
  resource_group_name = azurerm_resource_group.cis.name
  short_name          = "cisalerts"
}

# PRESENT (5.2.1) – Create Policy Assignment alert exists
resource "azurerm_monitor_activity_log_alert" "policy_create" {
  name                = "alert-policy-create"
  resource_group_name = azurerm_resource_group.cis.name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current.subscription_id}"]

  criteria {
    operation_name = "Microsoft.Authorization/policyAssignments/write"
    category       = "Administrative"
  }
  action { action_group_id = azurerm_monitor_action_group.cis_5.id }
}

# ABSENT (5.2.2) – Delete Policy Assignment alert missing
# ABSENT (5.2.3) – NSG Create/Update alert missing
# ABSENT (5.2.4) – NSG Delete alert missing
# ABSENT (5.2.5) – Security Solution alert missing
# ABSENT (5.2.6) – SQL Server firewall rule Create/Update alert missing
# ABSENT (5.2.7) – Public IP Create/Update alert missing

###############################################################################
# CIS 6.1 – Ensure RDP access is restricted from the internet
# CIS 6.2 – Ensure SSH access is restricted from the internet
# CIS 6.3 – Ensure UDP access is restricted from the internet
# CIS 6.4 – Ensure Network Watcher is enabled
# CIS 6.5 – Ensure NSG flow logs are enabled and sent to Log Analytics
# CIS 6.6 – Ensure Network Watcher is enabled in all regions
###############################################################################
resource "azurerm_virtual_network" "cis_6" {
  name                = "cis-vnet"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.cis.location
  resource_group_name = azurerm_resource_group.cis.name
}

resource "azurerm_subnet" "cis_6" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.cis.name
  virtual_network_name = azurerm_virtual_network.cis_6.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_network_security_group" "cis_6" {
  name                = "cis-nsg"
  location            = azurerm_resource_group.cis.location
  resource_group_name = azurerm_resource_group.cis.name

  # FAILS CIS 6.1 – RDP open to internet
  security_rule {
    name                       = "rdp-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # FAILS CIS 6.2 – SSH open to internet
  security_rule {
    name                       = "ssh-any"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # FAILS CIS 6.3 – UDP unrestricted
  security_rule {
    name                       = "udp-any"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# FAILS CIS 6.4 / 6.6 – no azurerm_network_watcher resource
# FAILS CIS 6.5 – no azurerm_network_watcher_flow_log resource

###############################################################################
# CIS 7.1 – Ensure VM uses approved VM image
# CIS 7.2 – Ensure OS disk is encrypted with CMK
# CIS 7.3 – Ensure 'Unattached disks' are encrypted with CMK
# CIS 7.4 – Ensure VMs use managed disks
# CIS 7.5 – Ensure Azure Backup is enabled for VMs
# CIS 7.6 – Ensure only approved VM extensions are installed
# CIS 7.7 – Ensure Endpoint Protection is installed on VMs
###############################################################################
resource "azurerm_public_ip" "cis_7" {
  name                = "cis-pip"
  resource_group_name = azurerm_resource_group.cis.name
  location            = azurerm_resource_group.cis.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "cis_7" {
  name                = "cis-nic"
  location            = azurerm_resource_group.cis.location
  resource_group_name = azurerm_resource_group.cis.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.cis_6.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.cis_7.id
  }
}

resource "azurerm_windows_virtual_machine" "cis_7" {
  name                = "cis-vm"
  resource_group_name = azurerm_resource_group.cis.name
  location            = azurerm_resource_group.cis.location
  size                = "Standard_B2s"
  admin_username      = "labadmin"
  admin_password      = "LabOnly-NotReal-99!"

  network_interface_ids = [azurerm_network_interface.cis_7.id]

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    # FAILS CIS 7.2 – no disk_encryption_set_id (CMK)
    storage_account_type = "Standard_LRS"
  }

  # FAILS CIS 7.5 – no azurerm_backup_protected_vm resource for this VM
  # FAILS CIS 7.7 – no IaaSAntimalware extension
  # FAILS – no managed identity (CIS recommends MSI over credentials)
}

# FAILS CIS 7.3 – unattached disk with no encryption set
resource "azurerm_managed_disk" "cis_7_unattached" {
  name                 = "cis-unattached-disk"
  location             = azurerm_resource_group.cis.location
  resource_group_name  = azurerm_resource_group.cis.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32
  # disk_encryption_set_id omitted – FAILS CIS 7.3
}

###############################################################################
# CIS 8.1 – Ensure App Service Authentication is set on Azure App Service
# CIS 8.2 – Ensure web app redirects HTTP to HTTPS
# CIS 8.3 – Ensure web app uses the latest version of TLS encryption
# CIS 8.4 – Ensure web app has Register with Azure Active Directory enabled
# CIS 8.5 – Ensure web app is using the latest version of .NET
# CIS 8.6 – Ensure FTP deployments are disabled
###############################################################################
resource "azurerm_service_plan" "cis_8" {
  name                = "cis-asp"
  resource_group_name = azurerm_resource_group.cis.name
  location            = azurerm_resource_group.cis.location
  os_type             = "Windows"
  sku_name            = "B1"
}

resource "azurerm_windows_web_app" "cis_8" {
  name                = "cis-webapp-gap-001"
  resource_group_name = azurerm_resource_group.cis.name
  location            = azurerm_resource_group.cis.location
  service_plan_id     = azurerm_service_plan.cis_8.id

  # FAILS CIS 8.2 – HTTPS not enforced
  https_only = false

  site_config {
    # FAILS CIS 8.3 – TLS below 1.2
    minimum_tls_version = "1.0"
    # FAILS CIS 8.6 – FTP enabled
    ftps_state          = "AllAllowed"
  }

  # FAILS CIS 8.1 – auth_settings.enabled not true
  auth_settings { enabled = false }

  # FAILS CIS 8.4 – no identity block
}
