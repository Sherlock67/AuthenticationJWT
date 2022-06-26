using LoginRegistration.IdentityAuth;
using LoginRegistration.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ZendeskApi_v2.Models.Constants;

namespace LoginRegistration.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;


        public AuthenticateController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] Register register)
        {
            var userExists = await userManager.FindByNameAsync(register.UserName);
            if (userExists != null)
            {
                if (userExists != null)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            }
            ApplicationUser user = new ApplicationUser()
            {
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.UserName
            };
            var result = await userManager.CreateAsync(user, register.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });

            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }
        [HttpPost]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register register)
        {
            var userExists = await userManager.FindByNameAsync(register.UserName);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });

            ApplicationUser user = new ApplicationUser()
            {
                Email = register.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = register.UserName
            };
            var result = await userManager.CreateAsync(user, register.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });

            if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await roleManager.RoleExistsAsync(UserRoles.EndUser))
                await roleManager.CreateAsync(new IdentityRole(UserRoles.EndUser));

            if (await roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await userManager.AddToRoleAsync(user, UserRoles.Admin);
            }

            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            var user = await userManager.FindByNameAsync(login.UserName);
            if (user != null && await userManager.CheckPasswordAsync(user, login.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT: SecretKey"]));
                var token = new JwtSecurityToken(
                issuer: _configuration["JWT: ValidIssuer"],
                audience: _configuration["JWT: ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
        }
    }
}
