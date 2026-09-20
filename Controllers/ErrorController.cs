using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace ApiAutenticacao.Controllers
{
    [ApiController]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class ErrorController : ControllerBase
    {
        [Route("/error")]
        public async Task HandleError()
        {
            Response.ContentType = "application/json";
            Response.StatusCode = StatusCodes.Status500InternalServerError;

            var problemDetails = new
            {
                status = StatusCodes.Status500InternalServerError,
                title = "Erro Fatal",
                detail = "Ocorreu um erro interno no servidor.",
                instance = HttpContext.Request.Path
            };

            await Response.WriteAsync(JsonSerializer.Serialize(problemDetails));
        }
    }
}
