using Microsoft.AspNetCore.Mvc;

namespace KeyMvc.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
