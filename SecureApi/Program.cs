using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SecureApi.Models;
using SecureApi.Services;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = "MyVeryStrongSuperSecretJwtKey12345"; // 32+ chars
var issuer = "SecureApi";
var audience = "SecureApiUsers";

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SecureApi",
        Version = "v1"
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Введите JWT токен так: Bearer {your token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<AesEncryptionService>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

var users = new List<User>
{
    new("admin", "admin123", "admin"),
    new("user", "user123", "user")
};

app.MapPost("/login", (LoginRequest request) =>
{
    var user = users.FirstOrDefault(u =>
        u.Username == request.Username && u.Password == request.Password);

    if (user is null)
    {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds);

    var jwt = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { token = jwt, role = user.Role });
});

app.MapGet("/user", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        message = "Hello, authorized user!",
        name = user.Identity?.Name,
        role = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value
    });
}).RequireAuthorization(policy => policy.RequireRole("user", "admin"));

app.MapGet("/admin", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        message = "Hello, admin!",
        name = user.Identity?.Name,
        role = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value
    });
}).RequireAuthorization(policy => policy.RequireRole("admin"));

app.MapPost("/encrypt", (EncryptRequest request, AesEncryptionService aesService) =>
{
    var encrypted = aesService.Encrypt(request.Text);
    return Results.Ok(new { encrypted });
}).RequireAuthorization(policy => policy.RequireRole("admin", "user"));

app.MapPost("/decrypt", (DecryptRequest request, AesEncryptionService aesService) =>
{
    var decrypted = aesService.Decrypt(request.CipherText);
    return Results.Ok(new { decrypted });
}).RequireAuthorization(policy => policy.RequireRole("admin", "user"));

app.Run();

record LoginRequest(string Username, string Password);
record User(string Username, string Password, string Role);