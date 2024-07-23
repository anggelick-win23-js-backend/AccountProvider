using AccountProvider.RequestModels;
using Data.Contexts;
using Data.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace AccountProvider.Functions
{
    public class GetUser
    {
        private readonly ILogger<GetUser> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public GetUser(ILogger<GetUser> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [Function("GetUser")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();

            if (body != null)
            {
                var urr = JsonConvert.DeserializeObject<UserRetreivalRequest>(body);

                if (urr != null)
                {
                    var userInformation = _userManager.Users
                        .Include(x => x.Address)
                        .FirstOrDefault(x => x.Id == urr.Id);

                    if (userInformation != null)
                    {
                        return new OkObjectResult(userInformation);
                    }
                    return new NotFoundResult();
                }
            }
            return new BadRequestResult();
        }
    }
}
