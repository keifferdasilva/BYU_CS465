using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Migrations.Operations;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // Use a random 32-byte salt. Use a 32-byte digest.
        Byte[] salt = Utils.GetSalt();

        byte[] encodedPassword = Utils.Encoding.GetBytes(password);

        List<byte> list = new List<byte>();
        list.AddRange(salt);
        list.AddRange(encodedPassword);
        byte[] saltAndPass = list.ToArray();

        SHA256 hasher = SHA256.Create();
        // Use 100,000 iterations and the SHA256 algorithm.
        for(int i = 0; i < 100000; i++){
            saltAndPass = hasher.ComputeHash(saltAndPass);
        }
        
        // Encode as "Base64(salt):Base64(digest)"
        return Utils.EncodeSaltAndDigest(salt,saltAndPass);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        string[] words = hashedPassword.Split(":");
        (byte[] salt, byte[] hash) = Utils.DecodeSaltAndDigest(hashedPassword);
        List<byte> list = new List<byte>();
        list.AddRange(salt);
        list.AddRange(Utils.Encoding.GetBytes(providedPassword));
        byte[] newHash = list.ToArray();
        for(int i = 0; i < 100000; i++){
            newHash = SHA256.Create().ComputeHash(newHash);
        }
        if(newHash.SequenceEqual(hash)){
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }

}