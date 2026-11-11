using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiAutenticacao.Controllers;

// The Auth API validates signature, issuer, audience, expiration and
// SecurityStamp in its existing JwtBearer configuration (Program.cs).
// This endpoint reveals only the subject of a valid bearer token.
[ApiController]
[Route("internal/auth")]
public sealed class InternalAuthController : ControllerBase
{
    [HttpGet("validate")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult Validate()
    {
        var subject = User.FindFirst("sub")?.Value
                   ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!long.TryParse(subject, out var userId) || userId <= 0)
            return Unauthorized();

        Response.Headers.CacheControl = "no-store";
        return Ok(new { active = true, sub = userId.ToString() });
    }
}
