using Microsoft.AspNetCore.Identity;

namespace Data.Entities;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string? Biography { get; set; }
    public string? ProfileImage { get; set; } = "/images/icons/no-profile-picture.svg";
    public bool NewsletterSubscriber { get; set; }
    public int? AddressId { get; set; }
    public AddressEntity? Address { get; set; }
}
