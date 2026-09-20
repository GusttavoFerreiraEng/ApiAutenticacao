namespace ApiAutenticacao.common
{
    public static class AuthErrors
    {
        public static readonly Error EmailAlreadyExists = new("Auth.EmailAlreadyExists", "O e-mail fornecido já está em uso.");

        public static readonly Error InvalidCredentials = new("Auth.InvalidCredentials", "E-mail ou senha inválidos.");

        public static readonly Error UserNotFound = new("Auth.UserNotFound", "Usuário não encontrado.");

        public static readonly Error InvalidToken = new("Auth.InvalidToken", "Sessão inválida ou token expirado. Faça login novamente.");

        public static readonly Error AccountLocked = new("Auth.AccountLocked", "Sua conta foi bloqueada por excesso de tentativas. Tente novamente em 15 minutos.");
    }
}