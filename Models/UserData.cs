using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace JwtAuthentication.Models
{
    public class UserData
    {
        [Key]
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
