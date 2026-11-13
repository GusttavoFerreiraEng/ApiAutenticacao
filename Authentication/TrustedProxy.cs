using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ApiAutenticacao.Authentication;

// Somente o BFF, autenticado por segredo interno, pode informar o IP usado nos limites.
public static class TrustedProxy
{
    public static bool TryClientIp(HttpRequest request, string? key, out IPAddress? address)
    {
        address = null;
        if (string.IsNullOrWhiteSpace(key)) return false;
        var supplied = request.Headers["X-Prevention-Proxy-Key"].ToString();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(supplied))) return false;
        return IPAddress.TryParse(request.Headers["X-Prevention-Client-IP"].ToString(), out address);
    }
}
