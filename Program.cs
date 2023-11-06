using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtTesting
{
    class Program
    {
        static void Main()
        {
            var rsaParameters = GenerateRsaKey();

            string privateKeyPem = ExportPrivateKeyAsPem(rsaParameters);
            Console.WriteLine("Private Key (PEM format):");
            Console.WriteLine(privateKeyPem);

            string publicKeyPem = ExportPublicKeyAsPem(rsaParameters);
            Console.WriteLine("Public Key (PEM format):");
            Console.WriteLine(publicKeyPem);

            string jwt = GenerateJwt(rsaParameters);
            var valid = ValidateJwtUsingRsaParameters(jwt, rsaParameters);
            Console.WriteLine(valid);

            var publicKey = Convert.ToBase64String(rsaParameters.Modulus);
            Console.WriteLine(publicKey);
            valid = ValidateJwtUsingPublicKey(jwt, publicKey);
            Console.WriteLine(valid);

            var publicKeyFromPem = GetModulusFromPem(publicKeyPem);
            Console.WriteLine(publicKeyFromPem);
            valid = ValidateJwtUsingPublicKey(jwt, publicKeyFromPem);
            Console.WriteLine(valid);
        }

        static RSAParameters GenerateRsaKey()
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 2048;
                return rsa.ExportParameters(true); // Export private key
            }
        }

        static string GenerateJwt(RSAParameters rsaParameters)
        {
            string issuer = "awp.com";
            string audience = "awp";

            var rsaCng = new RSACng();
            rsaCng.ImportParameters(rsaParameters);

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = audience,
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(ClaimTypes.Name, "user"),
                }),
                Expires = DateTime.UtcNow.AddHours(1), // Set the expiration time as needed
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaCng), SecurityAlgorithms.RsaSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            string jwtToken = tokenHandler.WriteToken(token);

            Console.WriteLine(jwtToken);
            return jwtToken;
        }

        static bool ValidateJwtUsingRsaParameters(string token, RSAParameters rsaParameters)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var rsaCng = new RSACng();
                rsaCng.ImportParameters(rsaParameters);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,    // Customize based on your requirements
                    ValidateAudience = false,  // Customize based on your requirements
                    IssuerSigningKey = new RsaSecurityKey(rsaCng),
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                SecurityToken validatedToken;
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        static bool ValidateJwtUsingPublicKey(string token, string publicKey)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();

                var rsaParams = new RSAParameters
                {
                    Modulus = Convert.FromBase64String(publicKey),
                    Exponent = Convert.FromBase64String("AQAB") 
                };

                var rsaSecurityKey = new RsaSecurityKey(rsaParams);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,    
                    ValidateAudience = false,  
                    IssuerSigningKey = rsaSecurityKey,
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                SecurityToken validatedToken;
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }

        static string ExportPrivateKeyAsPem(RSAParameters privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(privateKey);
                var privateKeyBytes = rsa.ExportRSAPrivateKey();
                var builder = new StringBuilder();
                builder.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
                builder.AppendLine(Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END RSA PRIVATE KEY-----");
                return builder.ToString();
            }
        }

        static string ExportPublicKeyAsPem(RSAParameters publicKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(publicKey);
                var publicKeyBytes = rsa.ExportRSAPublicKey();
                var builder = new StringBuilder();
                builder.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
                builder.AppendLine(Convert.ToBase64String(publicKeyBytes, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END RSA PUBLIC KEY-----");
                return builder.ToString();
            }
        }

        static string GetModulusFromPem(string pem)
        {
            PemReader pemReader = new PemReader(new System.IO.StringReader(pem));
            var pemObject = pemReader.ReadObject();

            if (pemObject is RsaKeyParameters rsaParameters)
            {
                byte[] modulus = rsaParameters.Modulus.ToByteArrayUnsigned();
                string modulusString = Convert.ToBase64String(modulus);
                return modulusString;
            }
            else
            {
                throw new ArgumentException("Invalid public key data.");
            }
        }

    }

}