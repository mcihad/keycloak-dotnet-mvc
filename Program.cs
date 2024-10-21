using KeyMvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

Settings.Configuration = builder.Configuration;
// Add services to the container.

builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(options =>
{
    //Sets cookie authentication scheme
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(cookie =>
{
    //Sets the cookie name and maxage, so the cookie is invalidated.
    cookie.Cookie.Name = "sivasbeltr.cookie";
    cookie.Cookie.MaxAge = TimeSpan.FromMinutes(60);
    cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    cookie.SlidingExpiration = true;
})
.AddOpenIdConnect(options =>
{

    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    options.Authority = builder.Configuration.GetSection("Keycloak")["ServerRealm"];

    options.ClientId = builder.Configuration.GetSection("Keycloak")["ClientId"];

    options.ClientSecret = builder.Configuration.GetSection("Keycloak")["ClientSecret"];

    options.MetadataAddress = builder.Configuration.GetSection("Keycloak")["Metadata"];

    options.RequireHttpsMetadata = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");

    options.SaveTokens = true;

    options.ResponseType = OpenIdConnectResponseType.Code;

    options.NonceCookie.SameSite = SameSiteMode.Unspecified;
    options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;
    options.RequireHttpsMetadata = false;
    // There has been reported issues where token is reported as expired right after login while keycloak returned expiration value is good 
    // Setting 'ValidateLifetime = false' below may fix the issue
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "preferred_username",
        RoleClaimType = ClaimTypes.Role,
        ValidateIssuer = true,
        ValidateLifetime = true
    };

});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("users", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c =>(c.Value == "user") || (c.Value == "admin"))
         )
     );
    options.AddPolicy("admins", policy =>policy.RequireClaim(ClaimTypes.Role, "admin"));
    
    options.AddPolicy("noaccess", policy => policy.RequireClaim(ClaimTypes.Role, "noaccess"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
