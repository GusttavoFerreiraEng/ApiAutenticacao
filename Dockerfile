FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ApiAutenticacao.csproj .
RUN dotnet restore ApiAutenticacao.csproj
COPY . .
RUN dotnet publish ApiAutenticacao.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir -p /keys && chown app:app /keys
USER app
EXPOSE 5000
ENTRYPOINT ["dotnet", "ApiAutenticacao.dll"]
