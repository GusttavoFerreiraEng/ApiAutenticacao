namespace ApiAutenticacao.Authentication;

public static class SessionCookies
{
    public static void Write(HttpContext context, AuthSettings settings, (string AccessToken, string RefreshToken) credentials)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Cookies.Append("jwt", credentials.AccessToken, Options(settings, DateTimeOffset.UtcNow.AddMinutes(15)));
        context.Response.Cookies.Append("refreshToken", credentials.RefreshToken, Options(settings, DateTimeOffset.UtcNow.AddDays(7)));
    }
    private static CookieOptions Options(AuthSettings settings, DateTimeOffset expires) => new()
    { HttpOnly = true, Secure = settings.SecureCookies, SameSite = SameSiteMode.Strict, Path = "/", Expires = expires };
}
