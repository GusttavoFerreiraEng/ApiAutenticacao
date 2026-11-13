using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations;

public sealed class ChangePasswordDTOValidator : AbstractValidator<ChangePasswordDTO>
{
    public ChangePasswordDTOValidator()
    {
        RuleFor(x => x.SenhaAtual).NotEmpty().WithMessage("A senha atual é obrigatória.");
        RuleFor(x => x.NovaSenha)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage("A nova senha é obrigatória.")
            .MinimumLength(8).WithMessage("A nova senha deve ter no mínimo 8 caracteres.")
            .Must(password => System.Text.Encoding.UTF8.GetByteCount(password) <= 72)
            .WithMessage("A senha deve ter no máximo 72 bytes.")
            .NotEqual(x => x.SenhaAtual).WithMessage("A nova senha deve ser diferente da senha atual.");
    }
}
