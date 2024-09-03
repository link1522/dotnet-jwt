using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;

// using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace dotnet_jwt
{
    public class JwtHelpers
    {
        private readonly IConfiguration _configuration;

        public JwtHelpers(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(string userName, int expireMinute = 30)
        {
            var issuer = _configuration.GetValue<string>("JwtSettings:Issuer");
            var signKey = _configuration.GetValue<string>("JwtSettings:SignKey");

            var claims = new List<Claim>() {
                new Claim(JwtRegisteredClaimNames.Sub, userName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User"),
            };

            var userClaimsIdentity = new ClaimsIdentity(claims);
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Subject = userClaimsIdentity,
                Expires = DateTime.Now.AddMinutes(expireMinute),
                SigningCredentials = signingCredentials
            };

            var tokenHandler = new JsonWebTokenHandler();
            var serializeToken = tokenHandler.CreateToken(tokenDescriptor);

            return serializeToken;
        }
    }
}