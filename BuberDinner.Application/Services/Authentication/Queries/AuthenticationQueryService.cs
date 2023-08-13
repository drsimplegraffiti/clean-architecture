using BuberDinner.Application.Common.Errors;
using BuberDinner.Application.Common.Interfaces.Authentication;
using BuberDinner.Application.Common.Interfaces.Persistence;
using BuberDinner.Application.Services.Authentication.Common;
using BuberDinner.Domain.Common.Errors;
using BuberDinner.Domain.Entities;
using ErrorOr;
using FluentResults;

namespace BuberDinner.Application.Services.Authentication.Queries;

public class AuthenticationQueryService : IAuthenticationQueryService
{
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IUserRepository _userRepository;

    public AuthenticationQueryService(IJwtTokenGenerator jwtTokenGenerator, IUserRepository userRepository)
    {
        _jwtTokenGenerator = jwtTokenGenerator;
        _userRepository = userRepository;
    }

    public ErrorOr<AuthenticationResult> Login(string Email, string Password)
    {

        // 1. Check if user exists
        if (_userRepository.GetUserByEmail(Email) is not User user)
        {
            return Errors.Authentication.InvalidCredentials;
        }

        // 2. Check if password is correct
        if (user.Password != Password)
        {
            return Errors.Authentication.InvalidCredentials;
        }


        // 3. Create jwt token
        var token = _jwtTokenGenerator.GenerateToken(user);

        return new AuthenticationResult(
            user,
            token);
    }

}