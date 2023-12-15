using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace JwtAuthentication.Dtos
{
    public class RegistrationRequest
    {
        [Required]
        public required string Name { get; set; }
        [EmailAddress]
        public required string Email { get; set; } 
        [PasswordPropertyText]
        [Required]
        public required string Password { get; set; }
    }
}
