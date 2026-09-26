using ApiAutenticacao.common;

namespace ApiAutenticacao.common
{
    public enum ErrorType
    {
        Failure = 400,      // Erros de regra de negócio genéricos (BadRequest)
        Unauthorized = 401, // Credenciais inválidas ou token expirado
        Forbidden = 403,    // Conta bloqueada ou sem permissão
        NotFound = 404,     // Usuário/recurso não encontrado
        Conflict = 409      // E-mail já existe
    }
}