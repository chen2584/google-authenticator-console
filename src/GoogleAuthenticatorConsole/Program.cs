using System;

namespace GoogleAuthenticatorConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            //var googleAuthenticator = new GoogleAuthenticator();
            //Console.WriteLine(googleAuthenticator.GenerateSecretKey(10));

            var googleAuthenticator = new GoogleAuthenticator();
            var secretKey = googleAuthenticator.GenerateSecretKey();
            Console.WriteLine($"SecretKey is {secretKey}");

            var encodedSecretKey = googleAuthenticator.GetEncodedSecretKey(secretKey);
            Console.WriteLine($"Encoded SecretKey is {encodedSecretKey}");
            Console.WriteLine($"Decoded SecretKey is {googleAuthenticator.GetDecodedSecretKey(encodedSecretKey)}");
            Console.ReadLine();

            // var googleAuthenticator = new GoogleAuthenticator();

            // Console.Write("Input SecretKey: ");
            // var secretKeyInput = Console.ReadLine();

            // Console.Write("Input Pin: ");
            // var pinInput = Console.ReadLine();

            // var googleAuthenticator = new GoogleAuthenticator();
            // var currentPin = googleAuthenticator.GetPin(secretKeyInput, DateTime.UtcNow);

            // Console.WriteLine($"\nIs SecretKey: {secretKeyInput} has current PIN: {pinInput}?");
            // Console.WriteLine($"Result: {pinInput == currentPin}. (Current Pin: {currentPin})");
        }
    }
}
