using ApiAutenticacao.common;

namespace ApiAutenticacao.common
{
  public sealed record Error(string Code, string Description, ErrorType Type = ErrorType.Failure)
    {
        public static readonly Error None = new(string.Empty, string.Empty, ErrorType.Failure);  
        public static readonly Error NullValue = new("NullValue", "O valor fornecido é nulo.", ErrorType.Failure);
    }
}