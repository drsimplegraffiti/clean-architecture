using BuberDinner.Application.Common.Errors;
using BuberDinner.Application.Common.Interfaces.Authentication;
using BuberDinner.Application.Common.Interfaces.Persistence;
using BuberDinner.Domain.Common.Errors;
using BuberDinner.Domain.Entities;
using ErrorOr;
using FluentResults;

namespace BuberDinner.Application.Services.Authentication;

public class AuthenticationService : IAuthenticationService
{
    private readonly IJwtTokenGenerator _jwtTokenGenerator;
    private readonly IUserRepository _userRepository;

    public AuthenticationService(IJwtTokenGenerator jwtTokenGenerator, IUserRepository userRepository)
    {
        _jwtTokenGenerator = jwtTokenGenerator;
        _userRepository = userRepository;
    }

    public ErrorOr<AuthenticationResult> Login(string Email, string Password)
    {

        // 1. Check if user exists
        if(_userRepository.GetUserByEmail(Email) is not User user){
            return Errors.Authentication.InvalidCredentials;
        }

        // 2. Check if password is correct
        if(user.Password != Password){
            return Errors.Authentication.InvalidCredentials;
        }
      

        // 3. Create jwt token
        var token = _jwtTokenGenerator.GenerateToken(user);
        
        return new AuthenticationResult(
            user,
            token);
    }

    public ErrorOr<AuthenticationResult> Register(string FirstName, string LastName, string Email, string Password)
    {
        //1. Vakidate if user does not exist
        if(_userRepository.GetUserByEmail(Email) is not null){
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