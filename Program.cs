using System.Reflection.Metadata.Ecma335;
using System.Text;
using DotNetEnv; // Add this
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.SignalR;



var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AppDbContext>(options =>
options.UseInMemoryDatabase("MessageDb")
);

builder.Services.AddSingleton<IEncryptionService, EncryptionService>();

var jwtKey = Convert.FromBase64String(
    builder.Configuration["Authentication:Schemes:Bearer:SigningKeys:0:Value"] ?? throw new NullReferenceException("Missing JwtKey")

);


builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new SymmetricSecurityKey(jwtKey),
        ValidateIssuer = true,

        ValidateAudience = true,
        ValidateLifetime = true,
        ValidIssuer = "dotnet-user-jwts",
        ValidAudience = "http://localhost:5050"

    };
});


builder.Services.AddAuthorization();



var app= builder.Build();


app.MapGet("/", () => "Hello World");

app.MapGet("/messages", async (AppDbContext dbContext) =>
{
    var messages = await dbContext.Messages.ToListAsync();
    
 return Results.Ok(messages);
});

app.MapGet("/messages/{id}", async(AppDbContext dbContext, int id) =>
{    var messages = await dbContext.Messages.FindAsync(id);

    if(messages ==null)
    return Results.NotFound("Message does not exist");
return Results.Ok(messages.Text);

});


app.MapPost("/messages", async (HttpContext context, AppDbContext dbContext, MessageDto messageDto, IEncryptionService encryptionService) =>
{
    var user = context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if(user ==null) return Results.BadRequest("Email required");
if (string.IsNullOrWhiteSpace(messageDto.Text) || messageDto.Text.Length > 500)
    {
        return Results.BadRequest("Invalid message length");
    }
    var encryptedText = encryptionService.Encrypt(messageDto.Text);

    var message = new Message
    {
        Text = encryptedText,
        User= user
    };

    dbContext.Messages.Add(message);
    await dbContext.SaveChangesAsync();
    return Results.Created($"/messages/{message.Id}", message.Text);
}).RequireAuthorization();



app.Run();

public record MessageRequest(string message);

internal interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class EncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public EncryptionService(IConfiguration config)
    {
        _key = Encoding.UTF8.GetBytes(config["EncryptionKey"]
        ?? throw new NullReferenceException("Set Encryption Key"));
        _iv = Encoding.UTF8.GetBytes(config["EncryptionIv"]
        ?? throw new NullReferenceException("Set Encryption IV"));
    }
    


    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var write = new StreamWriter(cs))
        {
            write.Write(plainText);
            write.Flush();
        }
        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        var buffer = Convert.FromBase64String(cipherText);
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(buffer);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        return reader.ReadToEnd();
    }
}


public class MessageDto
{
    required public string Text {get; set;}
}

public class Message{
   public int Id {get;set;}
   required public string Text {get;set;}
   required public string User {get;set;}

}


public class AppDbContext : DbContext
{
    public DbSet<Message> Messages {get;set;}
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options){}
}