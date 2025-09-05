output "deployment_status" {
  description = "Status do deployment"
  value = {
    server_host     = var.server_host
    app_version     = var.app_version
    deploy_directory = var.deploy_directory
    deployment_time = timestamp()
  }
}
