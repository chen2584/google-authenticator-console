using System;

namespace GoogleAuthenticatorConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            //var googleAuthenticator = new GoogleAuthenticator();
            //Console.WriteLine(googleAuthenticator.GenerateSecretKey(10));

            Console.Write("Input SecretKey: ");
            var secretKeyInput = Console.ReadLine();

            Console.Write("Input Pin: ");
            var pinInput = Console.ReadLine();

            var googleAuthenticator = new GoogleAuthenticator();
            var currentPin = googleAuthenticator.GetCurrentPin(secretKeyInput);

            Console.WriteLine($"\nIs SecretKey: {secretKeyInput} has current PIN: {pinInput}?");
            Console.WriteLine($"Result: {pinInput == currentPin}. (Current Pin: {currentPin})");
        }
    }
}
