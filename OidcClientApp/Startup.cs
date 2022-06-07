using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(OidcClientApp.Startup))]

namespace OidcClientApp
{
    public class Startup
    {
        const string _authority = "http://localhost:8080/auth/realms/master";
        const string _clientId = "mvc";
        const string _clientSecret = "zsUVAN53X6qCMzpjefCTBrwpenEEl3Ha";
        const string _redirectUrl = "https://localhost:44301/";

        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType("Cookies");

            // Important point : to be in SSL otherwise, there will be cookie issues.
            // IIS Express reserves the 443XX range to expose https
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                Authority = _authority,
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                RedirectUri = _redirectUrl,
                ResponseType = OpenIdConnectResponseType.Code,
                RedeemCode = true,

                TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = false, // This is a simplification
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = OnSecurityTokenValidated,
                    //AuthenticationFailed = OnAuthenticationFailed,
                },

                // When Identity Provider only exposes http (Eg: local instances)
                RequireHttpsMetadata = false
            });
            ;
        }

        private Task OnSecurityTokenValidated(SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", notification.ProtocolMessage.AccessToken));
            return Task.CompletedTask;
        }
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // See https://docs.microsoft.com/en-us/answers/questions/137574/azure-active-directory-authentication-error-owin.html
            if (context.Exception.Message.Contains("IDX21323"))
            {
                context.HandleResponse();
                context.OwinContext.Authentication.Challenge();
            }
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }
}