using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PSE.Identity.API.Data;
using PSE.Identity.API.Extensions;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

#region CONNECTION
builder.Services.AddDbContext<ApplicationDbContext>(optionsAction: options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
#endregion

#region JWT
var appSettingsSection = builder.Configuration.GetSection("AppSettings");
builder.Services.Configure<AppSettings>(appSettingsSection);

var appSettings = appSettingsSection.Get<AppSettings>();
var key = Encoding.ASCII.GetBytes(appSettings.Secret);

builder.Services.AddAuthentication(configureOptions: options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(
    bearerOptions =>
    {
        bearerOptions.RequireHttpsMetadata = true;
        bearerOptions.SaveToken = true;
        bearerOptions.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = appSettings.ValidIn,
            ValidIssuer = appSettings.Issuer
        };
    }
);
#endregion

#region BUILD & CONTROLLERS
builder.Services.AddControllers();
builder.Services.AddDefaultIdentity<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddEndpointsApiExplorer();
#endregion

#region SWAGGER

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "PommeStore Enterprise Identity API",
        Description = "Identity project. This is a personal project to practice .NET Skills.",
        Contact = new OpenApiContact() { Name = "Rafael Teixeira", Email = "rafael.ot@outlook.com" },
        License = new OpenApiLicense() { Name = "MIT", Url = new Uri(uriString: "https://opensource.org/licenses/MIT") }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "v1")
    );
}

#endregion

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
