using ApiAutenticacao.common;

namespace ApiAutenticacao.common
{
    public static class AuthErrors
    {
        // 409: Conflito
        public static readonly Error EmailAlreadyExists = new("Auth.EmailAlreadyExists", "O e-mail fornecido já está em uso.", ErrorType.Conflict);
        public static readonly Error UserAlreadyHasRole = new("Auth.UserAlreadyHasRole", "O usuário já possui a função especificada.", ErrorType.Conflict);

        // 401: Não autenticado
        public static readonly Error InvalidCredentials = new("Auth.InvalidCredentials", "E-mail ou senha inválidos.", ErrorType.Unauthorized);
        public static readonly Error InvalidToken = new("Auth.InvalidToken", "Sessão inválida ou token expirado. Faça login novamente.", ErrorType.Unauthorized);

        // 404: Não encontrado
        public static readonly Error UserNotFound = new("Auth.UserNotFound", "Usuário não encontrado.", ErrorType.NotFound);

        // 403: Sem permissão / Bloqueado
        public static readonly Error AccountLocked = new("Auth.AccountLocked", "Sua conta foi bloqueada por excesso de tentativas. Tente novamente em 15 minutos.", ErrorType.Forbidden);
        public static readonly Error Unauthorized = new("Auth.Unauthorized", "Acesso não autorizado. Você não tem permissão para acessar este recurso.", ErrorType.Forbidden);

        // 400: Requisição inválida
        public static readonly Error InvalidRole = new("Auth.InvalidRole", "Função inválida. A função fornecida não é reconhecida.");
    }
}