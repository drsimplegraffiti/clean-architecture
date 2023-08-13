using BuberDinner.Application.Common.Errors;
using BuberDinner.Application.Common.Interfaces.Authentication;
using BuberDinner.Application.Common.Interfaces.Persistence;
using BuberDinner.Application.Services.Authentication.Common;
using BuberDinner.Domain.Common.Errors;
using BuberDinner.Domain.Entities;
using ErrorOr;
using FluentResults;

namespace BuberDinner.Application.Services.Authentication.Commands;

public class AuthenticationCommandService : IAuthenticationCommandService
{
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IUserRepository _userRepository;

    public AuthenticationCommandService(IJwtTokenGenerator jwtTokenGenerator, IUserRepository userRepository)
    {
        _jwtTokenGenerator = jwtTokenGenerator;
        _userRepository = userRepository;
    }



    public ErrorOr<AuthenticationResult> Register(string FirstName, string LastName, string Email, string Password)
    {
        //1. Vakidate if user does not exist
        if (_userRepository.GetUserByEmail(Email) is not null)
        {
            return Errors.User.DuplicateEmail;
        }

        //2. create user (generate unique id) & persist to db
        var user = new User
        {
            FirstName = FirstName,
            LastName = LastName,
            Email = Email,
            Password = Password
        };

        _userRepository.Add(user);
        // 3. create jwt token
        var token = _jwtTokenGenerator.GenerateToken(user);

        return new AuthenticationResult(
           user,
            token);
    }
}