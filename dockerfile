#  Build (Usa o SDK do .NET 10 para compilar)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

# Cria uma pasta virtual chamada "app" DENTRO do container
WORKDIR /app

# Copia apenas o arquivo de projeto para dentro do container e restaura (Cache)
COPY *.csproj ./
RUN dotnet restore

# Copia todo o restante do código da sua máquina para o container
COPY . ./
# Compila o projeto
RUN dotnet build -c Release -o /app/build

# Publish
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Runtime (Usa apenas a imagem de execução do .NET 10, bem mais leve)
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Expõe a porta
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

# ATENÇÃO: Confirme se o nome da DLL gerada é o mesmo do seu projeto
ENTRYPOINT ["dotnet", "ApiAutenticacao.dll"]