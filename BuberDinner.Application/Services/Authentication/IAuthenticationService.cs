using BuberDinner.Application.Common.Errors;
using ErrorOr;

namespace BuberDinner.Application.Services.Authentication;

public interface IAuthenticationService
{
  ErrorOr<AuthenticationResult> Register(string FirstName, string LastName, string Email, string Password);
   ErrorOr<AuthenticationResult> Login(string Email, string Password);
}