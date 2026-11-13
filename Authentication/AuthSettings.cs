namespace ApiAutenticacao.Authentication;

public sealed class AuthSettings(IConfiguration configuration, IWebHostEnvironment environment)
{
    public bool GoogleEnabled => configuration.GetValue<bool>("Authentication:Google:Enabled");
    public bool LocalEnabled => !string.Equals(configuration["Authentication:Mode"], "GoogleOnly", StringComparison.OrdinalIgnoreCase);
    public string PublicOrigin => (configuration["PublicBaseUrl"] ?? "http://localhost:3000").TrimEnd('/');
    public bool SecureCookies => PublicOrigin.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || environment.IsProduction();
    public string Url(string path) => PublicOrigin + path;
    public void Validate()
    {
        var mode = configuration["Authentication:Mode"] ?? "Hybrid";
        if (!string.Equals(mode,"Hybrid",StringComparison.OrdinalIgnoreCase) && !string.Equals(mode,"GoogleOnly",StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Authentication:Mode deve ser Hybrid ou GoogleOnly.");
        if (!Uri.TryCreate(PublicOrigin, UriKind.Absolute, out var origin) || origin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment) || !string.IsNullOrEmpty(origin.UserInfo) ||
            (origin.Scheme != "https" && !(origin.Scheme == "http" && origin.IsLoopback)))
            throw new InvalidOperationException("PublicBaseUrl deve ser uma origem HTTPS, ou localhost HTTP em desenvolvimento.");
        if (environment.IsProduction() && origin.Scheme != "https") throw new InvalidOperationException("HTTPS obrigatório em produção.");
        if (System.Text.Encoding.UTF8.GetByteCount(configuration["jwt:Key"] ?? "") < (environment.IsProduction() ? 64 : 32))
            throw new InvalidOperationException("JWT_KEY deve ter ao menos 32 bytes em desenvolvimento e 64 em produção.");
        if (environment.IsProduction() && (configuration["Proxy:SharedKey"]?.Length ?? 0) < 64)
            throw new InvalidOperationException("Configure BFF_PROXY_KEY com ao menos 64 caracteres em produção.");
        if (!LocalEnabled && !GoogleEnabled) throw new InvalidOperationException("GoogleOnly exige autenticação Google habilitada.");
        if (GoogleEnabled && (string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientId"]) ||
            string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientSecret"])))
            throw new InvalidOperationException("Configure GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no ambiente.");
    }
}
