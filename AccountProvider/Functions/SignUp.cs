using AccountProvider.RequestModels;
using Data.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AccountProvider.Functions
{
    public class SignUp
    {
        private readonly ILogger<SignUp> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public SignUp(ILogger<SignUp> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [Function("SignUp")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();

            if (body != null)
            {
                var urr = JsonConvert.DeserializeObject<UserRegistrationRequest>(body);

                //Validate the model due to Modelstate.isvalid doesnt exists here 
                if (urr != null && urr.Email != null && urr.Password!= null && urr.FirstName!= null && urr.LastName!= null)
                {
                    ApplicationUser user = new ApplicationUser
                    {
                        UserName = urr.Email,
                        Email = urr.Email,
                        FirstName = urr.FirstName,
                        LastName = urr.LastName,
                        
                    };

                    var result = await _userManager.CreateAsync(user, urr.Password);

                    if (result.Succeeded)
                    {
                        return new OkObjectResult(result);
                    }
                    else if (result.Errors.Any(x => x.Code == "DuplicateUserName"))
                    {
                        return new ConflictObjectResult(result);
                    }
                }
            }
            return new BadRequestResult();
        }
    }
}
