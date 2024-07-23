namespace AccountProvider.RequestModels;

public class UserSignInRequest
{
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public bool IsPersistent { get; set; } = false;
}