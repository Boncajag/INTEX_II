using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]")]
//[Authorize]
public class UserController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;

    public UserController(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpGet("info")]
    public async Task<IActionResult> GetUserInfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            email = user.Email,
            isEmailConfirmed = user.EmailConfirmed,
            roles = roles
        });
    }

    [HttpGet("mfa/setup")]
    //[Authorize] // only for logged-in users
    public async Task<IActionResult> GetMfaSetup()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user == null)
            return Unauthorized();

        // Check if user already has a key, or generate one
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var email = await _userManager.GetEmailAsync(user);

        // Format URI for Authenticator apps (QR code compatible)
        var qrCodeUri = GenerateQrCodeUri("Microsoft Authenticator", email, key);

        return Ok(new
        {
            sharedKey = key,
            authenticatorUri = qrCodeUri
        });
    }

    private string GenerateQrCodeUri(string appName, string email, string key)
    {
        return $"otpauth://totp/{appName}:{email}?secret={key}&issuer={appName}&digits=6";
    }

}
