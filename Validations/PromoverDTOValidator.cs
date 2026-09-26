using FluentValidation;
using ApiAutenticacao.DTOs;

namespace ApiAutenticacao.Validations;

public sealed class PromoverDTOValidator : AbstractValidator<PromoverDTO>
{
    public PromoverDTOValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        
    }
}
