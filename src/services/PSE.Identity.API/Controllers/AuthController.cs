using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PSE.Identidade.API.Models;
using PSE.Identity.API.Extensions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PSE.Identity.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppSettings _appSettings;

        public AuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IOptions<AppSettings> appSettings)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _appSettings = appSettings.Value;
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register(UserRegister userRegister)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = new IdentityUser
            {
                UserName = userRegister.Email,
                Email = userRegister.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, userRegister.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return Ok(await GerarJwt(userRegister.Email));
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<ActionResult> Login(UserLogin userLogin)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password, false, true);

            if (result.Succeeded)
            {
                return Ok(await GerarJwt(userLogin.Email));
            }

            return BadRequest();
        }

        private async Task<UserResponseLogin> GerarJwt(string email)
        {

            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);
            var userRolers = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

            foreach (var useRole in userRolers)
            {
                claims.Add(new Claim("role", useRole));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = _appSettings.Issuer,
                Audience = _appSettings.ValidIn,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpireTimeHour),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), algorithm: SecurityAlgorithms.HmacSha256Signature)
            });

            var encodedToken = tokenHandler.WriteToken(token);

            return new UserResponseLogin
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(_appSettings.ExpireTimeHour).TotalSeconds,
                UserToken = new UserToken
                {
                    Id = user.Id,
                    Email = user.Email,
                    Claims = claims.Select(c => new UserClaim { Type = c.Type, Value = c.Value })
                }
            };
        }

        private static long ToUnixEpochDate(DateTime date) =>
            (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

    }
}
