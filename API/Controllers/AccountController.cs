using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _Context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _Context = context;
        }
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(registerDto registerDto)
        {
            if (await UserExists(registerDto.UserName)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key
            };
            _Context.Users.Add(user);
            await _Context.SaveChangesAsync();
             return new UserDto
        {
            Username = user.UserName,
            Token =  _tokenService.CreateToken(user),
           
        };
        }
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(loginDto loginDto)
        {
            var user = await _Context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.UserName);
            if (user == null) return Unauthorized("Invalid username");
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));
            for(int i=0;i<computedHash.Length;i++){
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }
             return new UserDto
        {
            Username = user.UserName,
            Token =  _tokenService.CreateToken(user),
            
        };


        }
        private async Task<bool> UserExists(string username)
        {
            return await _Context.Users.AnyAsync(x => x.UserName == username.ToLower());

        }

    }
}