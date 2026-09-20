using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations;

public sealed class ChangePasswordDTOValidator : AbstractValidator<ChangePasswordDTO>
{
    public ChangePasswordDTOValidator()
    {
        RuleFor(x => x.SenhaAtual).NotEmpty().WithMessage("A senha atual é obrigatória.");
        RuleFor(x => x.NovaSenha)
            .NotEmpty().WithMessage("A nova senha é obrigatória.")
            .MinimumLength(6).WithMessage("A nova senha deve ter no mínimo 6 caracteres.")
            .NotEqual(x => x.SenhaAtual).WithMessage("A nova senha deve ser diferente da senha atual.");
    }
}
