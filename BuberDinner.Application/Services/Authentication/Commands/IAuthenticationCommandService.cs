using BuberDinner.Application.Common.Errors;
using BuberDinner.Application.Services.Authentication.Common;
using ErrorOr;

namespace BuberDinner.Application.Services.Authentication.Commands;

public interface IAuthenticationCommandService
{
    ErrorOr<AuthenticationResult> Register(string FirstName, string LastName, string Email, string Password);
}