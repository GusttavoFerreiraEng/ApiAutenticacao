# API de Autenticação Enterprise

API RESTful desenvolvida em .NET 10 para autenticação e autorização de usuários com foco em segurança, boas práticas e arquitetura limpa. O projeto foi pensado como uma solução de referência para autenticação empresarial, com JWT, refresh tokens, cookies HttpOnly, recuperação de senha, confirmação de e-mail, limite de requisições e controle de acesso por roles.

## Visão geral

Essa API oferece um fluxo completo de autenticação e gerenciamento de usuários, incluindo:

- Cadastro de usuários
- Confirmação de e-mail
- Login com JWT e refresh token
- Cookies HttpOnly para armazenamento seguro de tokens
- Recuperação de senha
- Logout e logout em todos os dispositivos
- Alteração de senha
- Proteção de endpoints com autorização por roles
- Promover usuário para administrador
- Exclusão lógica de conta
- Health check da aplicação
- Rate limiting para rotas sensíveis

## Stack tecnológica

- .NET 10
- ASP.NET Core Web API
- C#
- Entity Framework Core
- MySQL 8
- JWT (Json Web Token)
- FluentValidation
- Swagger / OpenAPI
- xUnit (testes)
- BCrypt para hash de senhas
- Docker / Docker Compose

## Estrutura do projeto

```text
ApiAutenticacao/
├── Controllers/
│   └── AuthController.cs
├── Services/
├── Repositories/
├── Interfaces/
├── Data/
├── Models/
├── DTOs/
├── Validations/
├── Middlewares/
├── Common/
├── Migrations/
├── ApiAutenticacao.Tests/
├── appsettings.json
├── appsettings.Development.json
├── Program.cs
├── ApiAutenticacao.csproj
├── docker-compose.yml
├── dockerfile
├── ApiAutenticacao.http
├── README.md
└── .gitignore
```

### Camadas principais

- Controllers: expõem os endpoints HTTP
- Services: implementam a lógica de negócio
- Repositories: acesso e persistência com banco de dados
- DTOs: transportam dados sem expor entidades diretamente
- Validations: validações com FluentValidation
- Data: contexto do Entity Framework e configurações do banco
- Models: entidades do domínio
- Middlewares: interceptam e tratam erros ou comportamentos globais

## Requisitos

Antes de rodar o projeto, verifique se você tem instalado:

- .NET 10 SDK
- MySQL 8 ou Docker Compose
- Git
- Editor de código como VS Code, Rider ou Visual Studio

## Como executar

### Opção 1: usando Docker Compose (recomendado)

Este projeto já contém configuração para subir a API e o banco com Docker.

```bash
git clone https://github.com/GusttavoFerreiraEng/ApiAutenticacao.git
cd ApiAutenticacao
docker compose up --build
```

Após subir os containers:

- API: http://localhost:8080
- Swagger: http://localhost:8080/swagger
- MySQL: localhost:3306

### Opção 2: rodando localmente sem Docker

1. Configure a conexão com o banco em `appsettings.Development.json` ou `appsettings.json`
2. Crie o banco MySQL
3. Restaure os pacotes NuGet:

```bash
dotnet restore
```

4. Aplique as migrações:

```bash
dotnet ef database update
```

5. Inicie a aplicação:

```bash
dotnet run
```

Se estiver em ambiente de desenvolvimento, a aplicação habilita o Swagger automaticamente.

## Configuração dos ambientes

Os arquivos de configuração principais são:

- `appsettings.json`: configurações padrão
- `appsettings.Development.json`: ambiente local de desenvolvimento

Exemplo de variáveis esperadas:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=ApiAutenticacao;Uid=root;Pwd=sua_senha;"
  },
  "jwt": {
    "Key": "sua-chave-secreta",
    "Issuer": "ApiAutenticacao.Local",
    "Audience": "MeuFrontendApp"
  },
  "FrontendUrl": "http://localhost:3000",
  "SMTP_USER": "seu_email@gmail.com",
  "SMTP_PASS": "sua_senha_app",
  "SMTP_HOST": "smtp.gmail.com",
  "SMTP_PORT": "587"
}
```

Observação: a API usa `DotNetEnv` e também pode ser ajustada para leitura de variáveis de ambiente conforme necessário.

## Endpoints principais

Todos os endpoints usam o prefixo:

```text
/api/v1/Auth
```

### Autenticação e registro

- `POST /api/v1/Auth/register` - Cadastra um novo usuário
- `POST /api/v1/Auth/login` - Realiza login e cria cookies de sessão
- `POST /api/v1/Auth/refresh` - Renova tokens
- `POST /api/v1/Auth/logout` - Encerra a sessão atual
- `POST /api/v1/Auth/logout-all` - Desconecta todas as sessões do usuário

### Confirmação e recuperação

- `POST /api/v1/Auth/confirm-email` - Confirma o e-mail do usuário
- `POST /api/v1/Auth/resend-confirmation` - Reenvia o código de confirmação
- `POST /api/v1/Auth/forgot-password` - Solicita recuperação de senha
- `POST /api/v1/Auth/reset-password` - Redefine a senha

### Perfil e segurança

- `POST /api/v1/Auth/change-password` - Troca a senha autenticada
- `GET /api/v1/Auth/perfil` - Retorna o perfil do usuário autenticado
- `DELETE /api/v1/Auth/delete-account` - Exclui a conta autenticada

### Administração

- `POST /api/v1/Auth/promover/email` - Promove um usuário para administrador

### Saúde da aplicação

- `GET /health` - Verifica disponibilidade da API

## Segurança implementada

A API foi desenvolvida com foco em proteção real de autenticação. Entre as medidas aplicadas:

- JWT com validade curta
- Refresh token para renovação segura de sessão
- Cookies HttpOnly e Secure
- Rotação de tokens
- Blacklist e invalidação de sessões
- SecurityStamp para revogar tokens antigos
- Criptografia de senhas com BCrypt
- Rate limiting para login e rotas sensíveis
- CORS configurado para frontend
- Headers de segurança como X-Frame-Options, Referrer-Policy e CSP
- Validação de entrada com FluentValidation

## Testes

Para rodar a suíte de testes do projeto:

```bash
dotnet test
```

Se quiser executar apenas o projeto de testes:

```bash
dotnet test ApiAutenticacao.Tests
```

## Observações importantes

- O projeto usa MySQL como banco principal.
- A autenticação depende de JWT e cookies, então o frontend precisa aceitar cookies com credenciais.
- Em ambiente de produção, configure corretamente as chaves JWT, SMTP e strings de conexão.
- Não versionar segredos em repositório público. Use variáveis de ambiente ou arquivos de configuração locais seguros.

## Dica para o GitHub

Para deixar o repositório mais profissional no GitHub, você pode complementar esse README com:

- imagem do fluxo de autenticação
- arquitetura em diagramas
- exemplos de payloads de requisição
- vídeos ou GIFs do Swagger em uso
- badges (dotnet, license, docker, build status)

## Licença

Este projeto é de uso acadêmico e pessoal, a menos que você defina uma licença específica para o repositório.

## Conclusão

Esse README foi pensado para que qualquer desenvolvedor consiga entender rapidamente:

- para que a API serve
- como rodar em ambiente local
- quais tecnologias ela usa
- como os endpoints funcionam
- como ela se protege em nível de autenticação e segurança

Se quiser, posso também criar uma segunda versão mais “premium” para GitHub, com:

- badges
- screenshots do Swagger
- seção de exemplos de requisições
- versão mais visual e profissional
- README em inglês ou em português com estilo de portfolio
