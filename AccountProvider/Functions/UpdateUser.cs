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
    public class UpdateUser
    {
        private readonly ILogger<UpdateUser> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly DataContext _dataContext;

        public UpdateUser(ILogger<UpdateUser> logger, UserManager<ApplicationUser> userManager, DataContext dataContext)
        {
            _logger = logger;
            _userManager = userManager;
            _dataContext = dataContext;
        }

        [Function("UpdateUser")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {
            var body = await new StreamReader(req.Body).ReadToEndAsync();

            if (body != null)
            {
                var uur = JsonConvert.DeserializeObject<UserUpdateRequest>(body);

                var user = await _userManager.Users.FirstOrDefaultAsync(x => x.Email == uur!.Email);

                if (user != null)
                {
                    user.FirstName = uur!.FirstName; 
                    user.LastName = uur.LastName;
                    user.Biography = uur.Biography;
                    user.PhoneNumber = uur.PhoneNumber;
                    user.NewsletterSubscriber = uur.NewsletterSubscriber;
                    user.ProfileImage = uur.ProfileImage;

                    if (uur.Address != null)
                    {
                        var addressExists = await _dataContext.Addresses.FirstOrDefaultAsync(x =>
                        x.AddressLine1 == uur.Address.AddressLine1 &&
                        x.AddressLine2 == uur.Address.AddressLine2 &&
                        x.PostalCode == uur.Address.PostalCode &&
                        x.City == uur.Address.City);

                        if (addressExists != null)
                        {
                            user!.Address = addressExists;
                            user!.AddressId = addressExists.Id;
                        }
                        else
                        {
                            user!.Address = uur.Address;
                        }
                    }
                    else
                    {
                        user.Address = null;
                        user.AddressId = null;
                    }

                    try
                    {
                        var result = await _userManager.UpdateAsync(user);

                        if (result.Succeeded)
                        {
                            return new OkObjectResult(result);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                }
            }
            return new BadRequestResult();
        }
    }
}