using System.Security.Claims;
using ApiAutenticacao.Authentication;
using Asp.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ApiAutenticacao.Controllers;

[ApiController, ApiVersionNeutral]
[Route("api/v1/auth")]
public sealed class GoogleController(AuthSettings settings, GoogleAccountService accounts) : ControllerBase
{
    [HttpGet("providers")]
    public IActionResult Providers() { Response.Headers.CacheControl = "no-store"; return Ok(new { google = settings.GoogleEnabled, local = settings.LocalEnabled }); }
    [HttpGet("google/login"), EnableRateLimiting("ExternalLoginRateLimit")]
    public IActionResult Login() => settings.GoogleEnabled
        ? Challenge(new AuthenticationProperties { RedirectUri = settings.Url("/dashboard") }, GoogleAuthentication.Scheme)
        : StatusCode(503, new { error = "Login com Google ainda não configurado." });
    [HttpGet("google/pending")]
    public async Task<IActionResult> Pending()
    {
        var ticket = await HttpContext.AuthenticateAsync(GoogleAuthentication.PendingScheme);
        var identity = GoogleAccountService.Identity(ticket.Principal);
        Response.Headers.CacheControl = "no-store";
        return ticket.Succeeded && identity != null ? Ok(new { email = identity.Email }) : Unauthorized();
    }
    public sealed record LinkRequest(string? Password);
    [HttpPost("google/link"), EnableRateLimiting("ExternalLinkRateLimit")]
    public async Task<IActionResult> Link(LinkRequest request, CancellationToken ct)
    {
        if (!settings.GoogleEnabled) return StatusCode(503);
        var ticket = await HttpContext.AuthenticateAsync(GoogleAuthentication.PendingScheme);
        var identity = GoogleAccountService.Identity(ticket.Principal);
        if (!ticket.Succeeded || identity == null) return Unauthorized(new { error = "A confirmação expirou. Entre com Google novamente." });
        var id = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var credentials = await accounts.LinkAsync(identity, request.Password, long.TryParse(id,out var userId) ? userId : null, ct);
        if (credentials == null) return Unauthorized(new { error = "Não foi possível vincular. Confira a senha da conta existente ou tente novamente mais tarde." });
        SessionCookies.Write(HttpContext, settings, credentials.Value);
        await HttpContext.SignOutAsync(GoogleAuthentication.PendingScheme);
        return Ok(new { ok = true });
    }
}
