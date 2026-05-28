# =============================================================================
# Login Flow Tester Stack
#
# Entrypoint URL:
#   https://loginflow.nas.tokenet.de
#
# Architecture:
#   - Single Node/Express container with SQLite persistence
#   - App data on apps-pool/loginflow/data
#   - Traefik routing via file provider
#   - Image is built locally and pushed to registry.tokenet.de
# =============================================================================

resource "truenas_dataset" "loginflow" {
  pool = local.apps_pool
  path = "loginflow"
}

resource "truenas_dataset" "loginflow_data" {
  parent      = truenas_dataset.loginflow.id
  path        = "data"
  compression = "LZ4"
  uid         = local.truenas_user_id
  gid         = local.truenas_group_id
  mode        = "750"
}

resource "truenas_file" "loginflow_route" {
  path = "/mnt/${local.apps_pool}/traefik/config/loginflow.yml"
  uid  = 0
  gid  = 0
  mode = "0644"

  content = yamlencode({
    http = {
      routers = {
        loginflow = {
          rule        = "Host(`${local.app_host}`)"
          entryPoints = ["web", "websecure"]
          service     = "loginflow-svc"
          tls = {
            certResolver = "route53"
          }
        }
      }

      services = {
        loginflow-svc = {
          loadBalancer = {
            servers = [{ url = "http://127.0.0.1:${local.app_port}" }]
          }
        }
      }
    }
  })
}

resource "null_resource" "docker_registry_auth" {
  triggers = {
    registry_username = data.terraform_remote_state.core_k8s.outputs.registry_pull_username
    registry_password = data.terraform_remote_state.core_k8s.outputs.registry_pull_password
  }

  provisioner "local-exec" {
    command = <<-EOT
      ssh -o StrictHostKeyChecking=no -i /Users/keller/repos/_infra/.ssh/truenas_ed25519 root@${local.truenas_ip} \
        "echo '${data.terraform_remote_state.core_k8s.outputs.registry_pull_password}' | docker login registry.${local.domain_name} -u '${data.terraform_remote_state.core_k8s.outputs.registry_pull_username}' --password-stdin"
    EOT
  }
}

resource "truenas_app" "loginflow" {
  name       = "loginflow"
  custom_app = true

  compose_config = yamlencode({
    services = {
      loginflow = {
        image       = "registry.tokenet.de/tobisk/loginflow-tester:latest"
        pull_policy = "always"
        restart     = "unless-stopped"
        ports       = ["${local.app_port}:8080"]
        user        = "${local.truenas_user_id}:${local.truenas_group_id}"

        environment = {
          NODE_ENV      = "production"
          PORT          = "8080"
          DATABASE_PATH = "/data/loginflow.db"
          PUBLIC_ORIGIN = "https://${local.app_host}"
          RP_ID         = local.app_host
          RP_NAME       = "Login Flow Tester"
        }

        volumes = [
          "${truenas_dataset.loginflow_data.full_path}:/data",
        ]
      }
    }
  })

  restart_triggers = {
    route_checksum = truenas_file.loginflow_route.checksum
  }

  depends_on = [
    truenas_dataset.loginflow_data,
    truenas_file.loginflow_route,
    null_resource.docker_registry_auth,
  ]
}

output "loginflow_url" {
  value = "https://${local.app_host}"
}
