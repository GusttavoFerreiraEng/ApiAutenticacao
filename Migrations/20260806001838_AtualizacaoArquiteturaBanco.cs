using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ApiAutenticacao.Migrations
{
    /// <inheritdoc />
    public partial class AtualizacaoArquiteturaBanco : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RowVersion",
                table: "Users",
                type: "timestamp(6)",
                rowVersion: true,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RowVersion",
                table: "Users");
        }
    }
}
