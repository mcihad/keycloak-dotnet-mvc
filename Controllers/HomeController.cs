using KeyMvc.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace KeyMvc.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }


        [Authorize(Policy = "admins")]
        public IActionResult AuthenticationAdmin()
        {
            return View();
        }

        [Authorize(Policy = "noaccess")]
        public IActionResult AuthenticationNoAccess()
        {
            //Test that your identity does not have this claim attaced
            return View();
        }

        [Authorize(Roles ="admin")]
        public IActionResult AdminPage()
        {
            return View();
        }

        [Authorize(Roles = "user")]
        public IActionResult UserPage()
        {
            return View();
        }

        public IActionResult Logout()
        {
           return new SignOutResult(
            [
                OpenIdConnectDefaults.AuthenticationScheme,
                CookieAuthenticationDefaults.AuthenticationScheme
            ]);
        }


        [Authorize]
        public async Task<IActionResult> AuthenticationAsync()
        {

            //Find claims for the current user
            ClaimsPrincipal currentUser = this.User;
            //Get username, for keycloak you need to regex this to get the clean username
            var currentUserName = currentUser.FindFirst(ClaimTypes.NameIdentifier).Value;
            //logs an error so it's easier to find - thanks debug.
            _logger.LogError(currentUserName);

            //Debug this line of code if you want to validate the content jwt.io
            string accessToken = await HttpContext.GetTokenAsync("access_token");
            string idToken = await HttpContext.GetTokenAsync("id_token");
            string refreshToken = await HttpContext.GetTokenAsync("refresh_token");



            IEnumerable<Claim> roleClaims = User.FindAll(ClaimTypes.Role);
            IEnumerable<string> roles = roleClaims.Select(r => r.Value);
            foreach (var role in roles)
            {
                _logger.LogError(role);
            }

            //Another way to display all role claims
            var currentClaims = currentUser.FindAll(ClaimTypes.Role).ToList();
            foreach (var claim in currentClaims)
            {
                _logger.LogError(claim.ToString());
            }

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}
