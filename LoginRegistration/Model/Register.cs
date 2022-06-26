using System.ComponentModel.DataAnnotations;

namespace LoginRegistration.Model
{
    public class Register
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
