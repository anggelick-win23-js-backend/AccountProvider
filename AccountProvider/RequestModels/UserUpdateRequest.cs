using Data.Entities;
using System.ComponentModel.DataAnnotations;

namespace AccountProvider.RequestModels;

public class UserUpdateRequest
{
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string? PhoneNumber { get; set; }
    public string? Biography { get; set; }
    public bool NewsletterSubscriber { get; set; }
    public string? ProfileImage { get; set; }
    public int? AddressId { get; set; }
    public AddressEntity? Address { get; set; }
}