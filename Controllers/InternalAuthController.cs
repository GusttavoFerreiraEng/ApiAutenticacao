using System.Globalization;
using System.Security.Claims;
using Asp.Versioning;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiAutenticacao.Controllers;

[ApiController]
[ApiVersionNeutral]
[Route("internal/auth")]
public class InternalAuthController : ControllerBase
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpGet("validate")]
    public IActionResult Validate()
    {
        // O middleware JWT valida assinatura, expiração e SecurityStamp no banco.
        var subject = User.FindFirst("sub")?.Value
            ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        Response.Headers.CacheControl = "no-store";
        if (!long.TryParse(subject, out var id) || id <= 0)
            return Unauthorized();

        return Ok(new { active = true, sub = id.ToString(CultureInfo.InvariantCulture) });
    }
}
