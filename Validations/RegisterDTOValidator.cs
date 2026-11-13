using FluentValidation;

namespace ApiAutenticacao.Validations
{
    public class RegisterDTOValidator : AbstractValidator<RegisterDTO>
    {
        public RegisterDTOValidator()
        {
            RuleFor(x => x.Email)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("O email é obrigatório.")
                .MaximumLength(256).WithMessage("O e-mail deve ter no máximo 256 caracteres.")
                .EmailAddress().WithMessage("O formato do email é inválido (exemplo@email.com).")
                .Matches(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").WithMessage("O formato do email é inválido (exemplo@email.com).");

            RuleFor(x => x.Password)
                .Cascade(CascadeMode.Stop)
                .NotEmpty().WithMessage("A senha é obrigatória.")
                .MinimumLength(8).WithMessage("A senha deve ter no mínimo 8 caracteres.")
                .Must(password => System.Text.Encoding.UTF8.GetByteCount(password) <= 72)
                .WithMessage("A senha deve ter no máximo 72 bytes.");
        }
    }
}
