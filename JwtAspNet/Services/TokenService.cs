using JwtAspNet.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAspNet.Services
{
    public class TokenService
    {
        public string Create(User user)
        {
            //Classe responsavel por gerar o token
            var handler = new JwtSecurityTokenHandler();

            //Converte para um array de bytes
            var key = Encoding.ASCII.GetBytes(Configuration.PrivateKey);
            //Assina o token
            var credentials = new SigningCredentials(
                //Cria uma chave simetrica, so aceita arrays de bytes como parametro
                new SymmetricSecurityKey(key),
                // Emcripita o token, a varios tipos de emcripitacao nesse SecurityAlgorithms.
                SecurityAlgorithms.HmacSha256);

            // guarda as informacoes do token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //Trata a parte de seguranca
                SigningCredentials = credentials,
                //Tempo de validade do token
                Expires = DateTime.UtcNow.AddHours(2),
                //Guarda as claims
                Subject = GenarateClaims(user)
            };

            //Cria o token
            var token = handler.CreateToken(tokenDescriptor);
            // Le o token e retorna
            return handler.WriteToken(token);
        }

        private static ClaimsIdentity GenarateClaims(User user)
        {
            var ci = new ClaimsIdentity();

            //Tipos especiais
            ci.AddClaim(new Claim("id", user.Id.ToString()));
            ci.AddClaim(new Claim(ClaimTypes.Name, user.Name));
            ci.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            ci.AddClaim(new Claim("image", user.Image));

            foreach(var role in user.Roles)
            {
                ci.AddClaim(new Claim(ClaimTypes.Role, role));
            }

            return ci;
        }
    }
}
