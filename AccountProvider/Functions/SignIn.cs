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

        public SignIn(
            ILogger<SignIn> logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [Function("SignIn")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            _logger.LogInformation("SignIn function triggered.");

            try
            {
                var body = await new StreamReader(req.Body).ReadToEndAsync();
                var signInRequest = JsonConvert.DeserializeObject<UserSignInRequest>(body);

                if (signInRequest == null || string.IsNullOrEmpty(signInRequest.Email) || string.IsNullOrEmpty(signInRequest.Password))
                {
                    _logger.LogError("Invalid sign-in request: Missing email or password.");
                    return new BadRequestResult();
                }

                var user = await _userManager.FindByEmailAsync(signInRequest.Email);
                if (user == null)
                {
                    _logger.LogWarning("Sign-in attempt failed: User not found.");
                    return new UnauthorizedResult();
                }

                var result = await _signInManager.CheckPasswordSignInAsync(user, signInRequest.Password, false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User signed in successfully.");
                    var token = GenerateJwtToken(user);
                    return new OkObjectResult(token);
                }
                else
                {
                    _logger.LogWarning("Sign-in attempt failed: Incorrect password.");
                    return new UnauthorizedResult();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while processing the sign-in request: {ex.Message}");
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null when generating a JWT token.");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtSecret = Environment.GetEnvironmentVariable("JwtSecret");

            if (string.IsNullOrEmpty(jwtSecret))
            {
                _logger.LogError("JwtSecret environment variable is not set.");
                throw new InvalidOperationException("JwtSecret environment variable is not set.");
            }

            var key = Encoding.UTF8.GetBytes(jwtSecret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.Email),
                }),
                Expires = DateTime.UtcNow.AddDays(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature), // Fixed typo here
                Issuer = "SiliconAccountProvider",
                Audience = "SiliconWebApplication"
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
