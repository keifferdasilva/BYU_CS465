using System.Buffers.Text;
using System.Text;

namespace App.Areas.Identity;

internal static class Utils {

    /// <summary>
    /// Encoding used to convert strings to and from bytes.
    /// </summary>
    public static Encoding Encoding { get => Encoding.ASCII; }

    /// <summary>
    /// Encodes a salt and a digest into a string.
    /// </summary>
    /// <param name="salt">Salt to encode.</param>
    /// <param name="digest">Digest to encode.</param>
    /// <returns>Encoded salt and digest.</returns>
    public static string EncodeSaltAndDigest(byte[] salt, byte[] digest) {
        // Encode as "Base64(salt):Base64(digest)"
        string encoded = System.Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(digest);
        return encoded;
    }

    /// <summary>
    /// Decodes a salt and a digest from a string.
    /// </summary>
    /// <param name="salt">Salt to decode.</param>
    /// <param name="digest">Digest to decode.</param>
    /// <returns>Decoded salt and digest.</returns>
    public static (byte[], byte[]) DecodeSaltAndDigest(string value) {
        // Decode as "Base64(salt):Base64(digest)"
        byte[] salt;
        byte[] hash;
        string[] saltAndHash = value.Split(':');
        salt = Convert.FromBase64String(saltAndHash[0]);
        hash = Convert.FromBase64String(saltAndHash[1]);
        return (salt, hash);
    }

    public static byte[] GetSalt(){
        byte[] salt = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(salt);
        return salt;
    }

}
