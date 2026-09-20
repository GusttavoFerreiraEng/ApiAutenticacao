namespace ApiAutenticacao.DTOs
{
    public class ConfirmEmailDTO
    {
        public required string Email { get; set; }
        public required string Code { get; set; }
    }
}
