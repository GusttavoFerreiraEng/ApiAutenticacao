using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations
{
    public class ResendConfirmationDTOValidator : AbstractValidator<ResendConfirmationDTO>
    {
        public ResendConfirmationDTOValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("O email é obrigatório.")
                .EmailAddress().WithMessage("O formato do email é inválido.");
        }
    }
}
