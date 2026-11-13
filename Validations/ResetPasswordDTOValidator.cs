using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations;

public sealed class ResetPasswordDTOValidator : AbstractValidator<ResetPasswordDTO>
{
    public ResetPasswordDTOValidator()
    {
        RuleFor(x => x.Email).NotEmpty().MaximumLength(256).EmailAddress();
        RuleFor(x => x.Token).NotEmpty();
        RuleFor(x => x.NovaSenha).Cascade(CascadeMode.Stop).NotEmpty().MinimumLength(8)
            .Must(password => System.Text.Encoding.UTF8.GetByteCount(password) <= 72)
            .WithMessage("A senha deve ter no máximo 72 bytes.");
    }
}
