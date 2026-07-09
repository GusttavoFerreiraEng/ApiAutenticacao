using ApiAutenticacao.Validations;
using Xunit;

namespace ApiAutenticacao.Tests
{
    public class RegisterDTOValidatorTests
    {
        [Fact]
        public void Deve_Dar_Erro_Quando_Email_For_Invalido()
        {
            var validador = new RegisterDTOValidator(); 
            
            var usuarioFalso = new RegisterDTO 
            { 
                Email = "batata", 
                Password = "senhaforte123" 
            };


            var resultado = validador.Validate(usuarioFalso);

            Assert.False(resultado.IsValid);
            
            Assert.Contains(resultado.Errors, erro => erro.PropertyName == "Email");
        }
        
        [Fact]
        public void Deve_Passar_Quando_Dados_Forem_Perfeitos()
        {
            var validador = new RegisterDTOValidator(); 
            var usuarioBom = new RegisterDTO 
            { 
                Email = "estagiario@teste.com", 
                Password = "senhaforte123" 
            };

            var resultado = validador.Validate(usuarioBom);

            Assert.True(resultado.IsValid);
        }
    }
}