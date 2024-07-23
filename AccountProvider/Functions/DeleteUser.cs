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
    public class DeleteUser
    {
        private readonly ILogger<DeleteUser> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public DeleteUser(ILogger<DeleteUser> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [Function("DeleteUser")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();
            var urr = JsonConvert.DeserializeObject<UserRemovalRequest>(body);

            if (urr != null)
            {
                var userToDelete = _userManager.Users.FirstOrDefault(x => x.Id == urr.Id);
                if (userToDelete != null)
                {
                    var result = await _userManager.DeleteAsync(userToDelete);

                    if (result.Succeeded)
                    {
                        return new OkResult();
                    }
                    return new BadRequestResult();
                }
                return new NotFoundResult();
            }
            return new BadRequestResult();
        }
    }
}