using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations
{
    public class ConfirmEmailDTOValidator : AbstractValidator<ConfirmEmailDTO>
    {
        public ConfirmEmailDTOValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("O email é obrigatório.")
                .EmailAddress().WithMessage("O formato do email é inválido.");

            RuleFor(x => x.Code)
                .NotEmpty().WithMessage("O código é obrigatório.")
                .Length(6).WithMessage("O código deve conter exatamente 6 dígitos.");
        }
    }
}
