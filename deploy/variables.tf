variable "server_host" {
  description = "IP ou hostname do servidor de produção"
  type        = string
}

variable "server_user" {
  description = "Usuário SSH para acessar o servidor"
  type        = string
  default     = "ubuntu"
}

variable "server_ssh_key" {
  description = "Chave SSH privada para acessar o servidor"
  type        = string
  sensitive   = true
}

variable "app_version" {
  description = "Versão da imagem Docker a ser deployada"
  type        = string
  default     = "latest"
}

variable "postgres_password" {
  description = "Senha do PostgreSQL"
  type        = string
  sensitive   = true
}

variable "session_secret" {
  description = "Chave secreta para as sessões"
  type        = string
  sensitive   = true
}

variable "deploy_directory" {
  description = "Diretório onde a aplicação será deployada no servidor"
  type        = string
  default     = "/opt/curupira"
}
