terraform {
  required_version = ">= 1.0"
  
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Criar arquivo docker-compose.yml no servidor
resource "null_resource" "create_docker_compose" {
  triggers = {
    app_version = var.app_version
    always_run  = timestamp()
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p ${var.deploy_directory}",
      "cd ${var.deploy_directory}"
    ]

    connection {
      type        = "ssh"
      host        = var.server_host
      user        = var.server_user
      private_key = var.server_ssh_key
    }
  }

  provisioner "file" {
    content = templatefile("${path.module}/docker-compose.yml.tpl", {
      app_version       = var.app_version
      postgres_password = var.postgres_password
      session_secret    = var.session_secret
    })
    destination = "${var.deploy_directory}/docker-compose.yml"

    connection {
      type        = "ssh"
      host        = var.server_host
      user        = var.server_user
      private_key = var.server_ssh_key
    }
  }

  provisioner "file" {
    content = templatefile("${path.module}/.env.tpl", {
      postgres_password = var.postgres_password
      session_secret    = var.session_secret
    })
    destination = "${var.deploy_directory}/.env"

    connection {
      type        = "ssh"
      host        = var.server_host
      user        = var.server_user
      private_key = var.server_ssh_key
    }
  }
}

# Deploy da aplicação
resource "null_resource" "deploy_app" {
  depends_on = [null_resource.create_docker_compose]

  triggers = {
    app_version = var.app_version
    always_run  = timestamp()
  }

  provisioner "remote-exec" {
    inline = [
      "cd ${var.deploy_directory}",
      "docker-compose pull",
      "docker-compose up -d",
      "docker system prune -af --volumes"
    ]

    connection {
      type        = "ssh"
      host        = var.server_host
      user        = var.server_user
      private_key = var.server_ssh_key
    }
  }
}
