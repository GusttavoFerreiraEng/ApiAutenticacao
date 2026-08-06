using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ApiAutenticacao.Middlewares
{
    public class GlobalExceptionHandler : IExceptionHandler
    {
        private readonly ILogger<GlobalExceptionHandler> _logger;

        public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
        {
            _logger = logger;
        }

        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            _logger.LogError(exception, "Ocorreu uma exceção não tratada: {Message}", exception.Message);

            httpContext.Response.ContentType = "application/json";

            if (exception is DbUpdateConcurrencyException)
            {
                httpContext.Response.StatusCode = StatusCodes.Status409Conflict;
                var response = new
                {
                    Mensagem = "Muitas requisições simultâneas para a mesma conta. Tente novamente em instantes."
                };
                await httpContext.Response.WriteAsync(JsonSerializer.Serialize(response), cancellationToken);
                return true;
            }

            var problemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "Ocorreu um erro interno no servidor.",
                Detail = "Nossa equipe técnica já foi notificada.",
                Instance = httpContext.Request.Path
            };

            httpContext.Response.StatusCode = problemDetails.Status.Value;
            await httpContext.Response.WriteAsync(JsonSerializer.Serialize(problemDetails), cancellationToken);

            return true;
        }
    }
}