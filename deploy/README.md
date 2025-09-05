# Deployment com OpenTofu

Este diretório contém a configuração do OpenTofu para fazer deploy da aplicação Curupira em um servidor dedicado.

## Como funciona

O OpenTofu gerencia apenas o **deployment** da aplicação, não a infraestrutura. Ele:

1. Cria os arquivos de configuração (`docker-compose.yml` e `.env`) no servidor
2. Executa os comandos Docker para atualizar e reiniciar a aplicação
3. Limpa imagens antigas do Docker

## Arquivos

- `main.tf`: Configuração principal do deployment
- `variables.tf`: Variáveis de entrada
- `outputs.tf`: Saídas do deployment
- `docker-compose.yml.tpl`: Template do docker-compose
- `.env.tpl`: Template das variáveis de ambiente

## Secrets necessários no GitHub

Configure os seguintes secrets no repositório GitHub:

- `DEPLOY_HOST`: IP ou hostname do servidor
- `DEPLOY_USERNAME`: Usuário SSH (ex: ubuntu)
- `DEPLOY_SSH_KEY`: Chave SSH privada para acessar o servidor
- `POSTGRES_PASSWORD`: Senha do PostgreSQL
- `SESSION_SECRET`: Chave secreta para sessões (gerada com `openssl rand -base64 32`)

## Como testar localmente

1. Instale o OpenTofu:

   ```bash
   # Ubuntu/Debian
   curl --proto '=https' --tlsv1.2 -fsSL https://get.opentofu.org/install-opentofu.sh -o install-opentofu.sh
   chmod +x install-opentofu.sh
   ./install-opentofu.sh --install-method deb
   ```

2. Navegue para o diretório de deploy:

   ```bash
   cd deploy
   ```

3. Inicialize o OpenTofu:

   ```bash
   tofu init
   ```

4. Crie um arquivo `terraform.tfvars` (não commitado):

   ```hcl
   server_host = "seu-servidor.com"
   server_user = "ubuntu"
   app_version = "latest"
   postgres_password = "sua-senha-postgres"
   session_secret = "sua-chave-secreta"
   ```

5. Planeje o deployment:

   ```bash
   tofu plan
   ```

6. Aplique as mudanças:
   ```bash
   tofu apply
   ```

## Vantagens desta abordagem

1. **Aprendizado gradual**: Você aprende OpenTofu sem mexer na infraestrutura
2. **Versionamento**: Todo o processo de deploy fica versionado
3. **Reprodutibilidade**: O deploy sempre acontece da mesma forma
4. **Rollback**: Fácil de reverter para versões anteriores
5. **Visibilidade**: Você vê exatamente o que está sendo executado

## Próximos passos

Depois de dominar esta parte, você pode expandir para:

1. Gerenciar configurações de nginx/proxy reverso
2. Configurar SSL/TLS automaticamente
3. Gerenciar backups do banco de dados
4. Monitoramento e logs
5. Múltiplos ambientes (staging/production)
