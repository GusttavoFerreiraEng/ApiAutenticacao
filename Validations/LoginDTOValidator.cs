using FluentValidation;

namespace ApiAutenticacao.Validations
{
    public class LoginDTOValidator : AbstractValidator<LoginDTO>
    {
        public LoginDTOValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("O email é obrigatório.")
                .EmailAddress().WithMessage("O formato do email é inválido (exemplo@email.com).");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("A senha é obrigatória.");
        }
    }
}