using Microsoft.AspNetCore.Identity;

namespace Domain
{
    public class AppUser : IdentityUser
    {
        public string Bio { get; set; }
        public string DisplayName { get; set; }
    }
}