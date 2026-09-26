namespace ApiAutenticacao.DTOs

{
public class PromoverDTO
{  
    [Required(ErrorMessage = "O campo 'Email' é obrigatório.")]
    public string Email { get; set; } = string.Empty;
}
}
