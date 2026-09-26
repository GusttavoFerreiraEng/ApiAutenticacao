public class RegisterDTO
{   
    [Required(ErrorMessage = "O campo 'Email' é obrigatório.")]
    public required string Email { get; set; }
    [Required(ErrorMessage = "O campo 'Password' é obrigatório.")]
    public required string Password { get; set; }
}