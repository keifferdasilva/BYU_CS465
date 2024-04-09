using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by PBKDF2.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using PBKDF2.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = Utils.GetSalt();
        
        byte[] encodedPassword = Utils.Encoding.GetBytes(password);


        // Use 100,000 iterations and the SHA256 algorithm.
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(encodedPassword, salt, 100000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);        
        
        // Encode as "Base64(salt):Base64(digest)"
        return Utils.EncodeSaltAndDigest(salt, hash);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        (byte[] salt, byte[] hash) = Utils.DecodeSaltAndDigest(hashedPassword);
        byte[] encodedPassword = Utils.Encoding.GetBytes(providedPassword);
        byte[] newHash = Rfc2898DeriveBytes.Pbkdf2(encodedPassword, salt, 100000, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
        if(newHash.SequenceEqual(hash)){
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }

}