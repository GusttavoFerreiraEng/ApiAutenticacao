using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations;

public sealed class ResetPasswordDTOValidator : AbstractValidator<ResetPasswordDTO>
{
    public ResetPasswordDTOValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Token).NotEmpty();
        RuleFor(x => x.NovaSenha).NotEmpty().MinimumLength(6);
    }
}
