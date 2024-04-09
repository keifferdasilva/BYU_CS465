using Microsoft.AspNetCore.Identity;

using BC = BCrypt.Net.BCrypt;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by BCrypt.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class BCryptHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using BCrypt.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use the EnhancedHashPassword function.
        // todo: Ensure that it uses at least 100,000 iterations, but no more than 200,000.
        return string.Empty;
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        return PasswordVerificationResult.Failed;
    }

}