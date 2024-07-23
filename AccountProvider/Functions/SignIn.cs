using AccountProvider.RequestModels;
using Data.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AccountProvider.Functions
{
    public class SignIn
    {
        private readonly ILogger<SignIn> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public SignIn(ILogger<SignIn> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> singInManager)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = singInManager;
        }

        [Function("SignIn")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            _logger.LogInformation("SignIn function triggered.");

            try
            {
                var body = await new StreamReader(req.Body).ReadToEndAsync();
                var signInRequest = JsonConvert.DeserializeObject<UserSignInRequest>(body);

                if (signInRequest != null && !string.IsNullOrEmpty(signInRequest.Email) && !string.IsNullOrEmpty(signInRequest.Password))
                {
                    var user = await _userManager.FindByEmailAsync(signInRequest.Email);
                    var result = await _signInManager.CheckPasswordSignInAsync(user, signInRequest.Password, false);

                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User signed in successfully.");

                        var token = GenerateJwtToken(user);
                        return new OkObjectResult(token);
                    }
                    else
                    {
                        _logger.LogError("Failed to sign in user.");
                        return new UnauthorizedResult();
                    }
                }
                else
                {
                    _logger.LogError("Invalid sign-in request.");
                    return new BadRequestResult();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while processing sign-in request: {ex.Message}");
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        public string GenerateJwtToken(ApplicationUser user)
        {
            if (user != null)
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JwtSecret"));

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                        new(ClaimTypes.Email, user.Email!),
                        new(ClaimTypes.Name, user.Email!),
                    }),
                    Expires = DateTime.Now.AddDays(2),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                    Issuer = "SiliconAccountProvider",
                    Audience = "SiliconWebApplication"
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return tokenString;
            }
            return null!;
        }
    }
}