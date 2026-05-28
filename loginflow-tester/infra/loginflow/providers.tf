# =============================================================================
# Login Flow Tester Stack — Provider Configuration
# =============================================================================

terraform {
  required_providers {
    truenas = {
      source  = "deevus/truenas"
      version = "~> 0.15"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

provider "truenas" {
  host        = local.truenas_ip
  auth_method = "ssh"

  ssh {
    port                 = 22
    user                 = "root"
    private_key          = file("${path.module}/../../.ssh/truenas_ed25519")
    host_key_fingerprint = "SHA256:ZQKVM49H4sS4WNjieH8Ae5HUzF2b5seQ+syM/Ce44UY"
  }
}

data "terraform_remote_state" "core_k8s" {
  backend = "local"
  config = {
    path = "${path.module}/../../k8s-stacks/core/terraform.tfstate"
  }
}
