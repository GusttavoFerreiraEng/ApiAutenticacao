using ApiAutenticacao.Validations;
using Xunit;

namespace ApiAutenticacao.Tests
{
    public class RegisterDTOValidatorTests
    {
        // A tag [Fact] avisa o C# que isso é um Teste Automatizado
        [Fact]
        public void Deve_Dar_Erro_Quando_Email_For_Invalido()
        {
            // 1. ARRANGE (A Preparação do Cenário)
            // Chamamos o nosso Segurança da Recepção
            var validador = new RegisterDTOValidator(); 
            
            // Criamos o usuário hacker tentando passar um email falso
            var usuarioFalso = new RegisterDTO 
            { 
                Email = "batata", 
                Password = "senhaforte123" 
            };

            // 2. ACT (A Ação)
            // Mandamos o Segurança avaliar o usuário
            var resultado = validador.Validate(usuarioFalso);

            // 3. ASSERT (A Verificação do Sênior)
            // Nós AFIRMAMOS que o resultado tem que ser FALSO (inválido)
            Assert.False(resultado.IsValid);
            
            // Nós AFIRMAMOS que tem que existir um erro especificamente no campo "Email"
            Assert.Contains(resultado.Errors, erro => erro.PropertyName == "Email");
        }
        
        [Fact]
        public void Deve_Passar_Quando_Dados_Forem_Perfeitos()
        {
            // 1. ARRANGE
            var validador = new RegisterDTOValidator(); 
            var usuarioBom = new RegisterDTO 
            { 
                Email = "estagiario@teste.com", 
                Password = "senhaforte123" 
            };

            // 2. ACT
            var resultado = validador.Validate(usuarioBom);

            // 3. ASSERT
            // Afirmamos que o segurança tem que deixar ele passar
            Assert.True(resultado.IsValid);
        }
    }
}