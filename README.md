```markdown
# 🛡️ API de Autenticação Enterprise (.NET 10)

Uma API RESTful desenvolvida em **C# (.NET 10)** focada em **Segurança da Informação** e **Arquitetura Limpa**. Este projeto não é apenas um CRUD de utilizadores, mas sim uma implementação de padrões de mercado para proteção de rotas, mitigação de ataques web (XSS, Força Bruta) e gestão segura de sessões.

## ✨ Principais Funcionalidades & Segurança

* **Autenticação Stateless (JWT):** Geração de Access Tokens de curta duração (15 minutos) para minimizar a janela de vulnerabilidade.
* **Rotação de Chaves (Refresh Tokens):** Implementação de Refresh Tokens opacos (com duração de 7 dias) guardados na base de dados para renovar a sessão silenciosamente, garantindo segurança sem prejudicar a experiência do utilizador.
* **Segurança de Transporte (HttpOnly Cookies):** Os tokens **não** são devolvidos no corpo da resposta (JSON) nem armazenados no `localStorage`. Viajam exclusivamente em cookies `HttpOnly` e `Secure`, bloqueando a interceção por scripts maliciosos (mitigação de XSS).
* **Estratégia de Invalidação (Blacklist):** Interceção de Logout no lado do servidor. Os tokens são guardados numa tabela de "Lista Negra" (Blacklist) no momento do logout. O *middleware* da API rejeita qualquer pedido feito com um token revogado, mitigando o problema natural de expiração do JWT.
* **Defesa de Infraestrutura (Rate Limiting):** Escudo anti-robôs configurado nativamente para a rota de *Login* (limite de 5 pedidos a cada 30 segundos), prevenindo ataques de força bruta (Brute Force) e DDoS.
* **Controlo de Acesso (RBAC):** Autorização baseada em cargos (Roles), separando permissões de utilizadores comuns e Administradores.
* **Proteção de Dados Sensíveis:** Encriptação irreversível de palavras-passe utilizando o algoritmo **BCrypt**.

## 🛠️ Tecnologias Utilizadas

* **Framework:** .NET 10 (ASP.NET Core Web API)
* **Linguagem:** C# 13
* **Base de Dados:** SQLite (leve e portátil para o desenvolvimento)
* **ORM:** Entity Framework Core
* **Validações:** FluentValidation (Separação das regras de negócio dos DTOs)
* **Testes Automatizados:** xUnit
* **Documentação:** Swagger (OpenAPI)

## 🏗️ Arquitetura do Projeto

O projeto segue princípios de separação de responsabilidades (Separation of Concerns):
- **Controllers:** Responsáveis apenas por receber pedidos HTTP, invocar o validador e devolver as respostas (HTTP Status Codes).
- **Services (`AuthService`):** Contêm o "coração" da aplicação. Toda a lógica de encriptação, geração de chaves criptográficas complexas e regras de negócio estão isoladas aqui.
- **DTOs (`Data Transfer Objects`):** Objetos que garantem que as entidades da base de dados (Models) nunca sejam expostas diretamente aos utilizadores.
- **Tests (`ApiAutenticacao.Tests`):** Projeto isolado com testes de unidade (xUnit) que valida os fluxos de entrada autonomamente e previne a injeção de dados inválidos.

## 🚀 Como Executar o Projeto Localmente

### Pré-requisitos
* [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) instalado.
* Um editor de código (Visual Studio, VS Code ou Rider).

### Passos
1. Faça o clone deste repositório:
   ```bash
   git clone [https://github.com/SEU-USUARIO/ApiAutenticacao.git](https://github.com/SEU-USUARIO/ApiAutenticacao.git)

```

2. Aceda à pasta do projeto:
```bash
cd ApiAutenticacao

```


3. Restaure os pacotes NuGet:
```bash
dotnet restore

```


4. Crie a base de dados e aplique as migrações do Entity Framework:
```bash
dotnet ef database update

```


5. Inicie a API:
```bash
dotnet run

```


6. Abra o navegador no endereço indicado na consola (geralmente `http://localhost:5019/swagger`) para explorar os *endpoints* interativamente através do Swagger.

## 🧪 Como Executar os Testes Automatizados

O projeto conta com uma suíte de testes de unidade focada na validação da entrada de dados. Para correr os testes, execute o seguinte comando na raiz do projeto:

```bash
dotnet test ApiAutenticacao.Tests

```

## 🗺️ Endpoints da API

* `POST /api/Auth/register` - Regista um novo utilizador (Validado via FluentValidation).
* `POST /api/Auth/login` - Autentica o utilizador e injeta os Cookies (Access e Refresh Tokens).
* `POST /api/Auth/refresh` - Renova o Access Token silenciosamente usando o Refresh Token.
* `POST /api/Auth/logout` - Invalida os tokens (Blacklist) e destrói os Cookies.
* `GET /api/Auth/perfil` - Rota protegida. Retorna os dados básicos do utilizador autenticado.
* `GET /api/Auth/admin` - Rota protegida. Acessível apenas para utilizadores com a *role* "Admin".
* `POST /api/Auth/promover/{email}` - Promove um utilizador ao cargo de Administrador.

---

*Desenvolvido como projeto de estudo avançado de segurança e arquitetura Back-end.*

```

```
