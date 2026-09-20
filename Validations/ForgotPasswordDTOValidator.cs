using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations
{
    public class ForgotPasswordDTOValidator : AbstractValidator<ForgotPasswordDTO>
    {
        public ForgotPasswordDTOValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("O e-mail é obrigatório.")
                .EmailAddress().WithMessage("O e-mail fornecido não é válido.");
        }
    }
}