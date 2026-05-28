# =============================================================================
# Login Flow Tester Stack — Shared Local Values
# =============================================================================

locals {
  domain_name = "tokenet.de"
  truenas_ip  = "192.168.42.250"

  truenas_user_id  = 1000
  truenas_group_id = 1000

  apps_pool = "apps-pool"

  app_host = "loginflow.nas.${local.domain_name}"
  app_port = 8592
}
