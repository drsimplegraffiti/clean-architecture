using BuberDinner.Application.Common.Errors;
using BuberDinner.Application.Services.Authentication;
using BuberDinner.Contracts.Authentication;
using BuberDinner.Domain.Common.Errors;
using ErrorOr;
using FluentResults;
using Microsoft.AspNetCore.Mvc;

namespace BuberDinner.Api.Controllers;

[Route("auth")] // you can use [Route("api/[controller]")] instead
public class AuthenticationController : ApiController
{
    private readonly IAuthenticationService _authenticationService;

    public AuthenticationController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        ErrorOr<AuthenticationResult> authResult = _authenticationService.Register(
            request.FirstName,
            request.LastName,
            request.Email,
            request.Password);

        return authResult.Match(
            authResult => Ok(MapAuthResult(authResult)),
            errors => Problem(errors));
    }


    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var authresult = _authenticationService.Login(
            request.Email,
            request.Password);

         if(authresult.IsError && authresult.FirstError == Errors.Authentication.InvalidCredentials)
        {
            return Problem(
                statusCode: StatusCodes.Status401Unauthorized,
                title: authresult.FirstError.Description);
        }

        return authresult.Match(
            authResult => Ok(MapAuthResult(authResult)),
            errors => Problem(errors));
    }

        private static AuthenticationResponse MapAuthResult(AuthenticationResult authResult)
    {
        return new AuthenticationResponse(
            authResult.User.Id,
            authResult.User.Email,
            authResult.User.FirstName,
            authResult.User.LastName,
            authResult.Token
        );
    }
}