using System.Net;
using ApiAutenticacao.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Moq;

namespace ApiAutenticacao.Tests;

public sealed class SecurityConfigurationTests
{
    [Fact]
    public void ClientIpRequiresInternalProxyProof()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.9";
        context.Request.Headers["X-Prevention-Client-IP"] = "198.51.100.9";
        var key = new string('a',64);
        Assert.False(TrustedProxy.TryClientIp(context.Request,key,out _));
        context.Request.Headers["X-Prevention-Proxy-Key"] = new string('b',64);
        Assert.False(TrustedProxy.TryClientIp(context.Request,key,out _));
        context.Request.Headers["X-Prevention-Proxy-Key"] = key;
        Assert.True(TrustedProxy.TryClientIp(context.Request,key,out var ip));
        Assert.Equal(IPAddress.Parse("198.51.100.9"),ip);
        context.Request.Headers["X-Prevention-Client-IP"] = "bad-ip, 198.51.100.9";
        Assert.False(TrustedProxy.TryClientIp(context.Request,key,out _));
    }

    [Theory]
    [InlineData("http://finance.example.com","GoogleOnly",true)]
    [InlineData("https://finance.example.com/path","GoogleOnly",true)]
    [InlineData("https://finance.example.com","GoogleOnly",false)]
    [InlineData("https://finance.example.com","unknown",true)]
    public void InvalidProductionSettingsFailClosed(string origin,string mode,bool google)
    {
        var env=new Mock<IWebHostEnvironment>();env.SetupGet(e=>e.EnvironmentName).Returns("Production");
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>
        {
            ["PublicBaseUrl"]=origin,["Authentication:Mode"]=mode,["Authentication:Google:Enabled"]=google.ToString(),
            ["Authentication:Google:ClientId"]="test-client",["Authentication:Google:ClientSecret"]="test-secret",
            ["jwt:Key"]=SessionApiFactory.SigningKey,["Proxy:SharedKey"]=new string('a',64)
        }).Build();
        Assert.Throws<InvalidOperationException>(()=>new AuthSettings(config,env.Object).Validate());
    }
}
