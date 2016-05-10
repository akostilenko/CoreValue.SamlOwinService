using System;
using System.IdentityModel.Metadata;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Kentor.AuthServices;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices.WebSso;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode;

namespace CoreValue.SamlOwinService
{
    public abstract class SamlServiceHandler : AuthenticationHandler<SamlServiceAuthenticationOptions>
    {
        protected async override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var result = CommandFactory.GetCommand(CommandFactory.AcsCommandName)
                .Run(await Context.ToHttpRequestData(), Options);

            var identities = result.Principal.Identities.Select(i =>
                new ClaimsIdentity(i, null, Options.SignInAsAuthenticationType, i.NameClaimType, i.RoleClaimType));

            var authProperties = (AuthenticationProperties)result.RelayData ?? new AuthenticationProperties();
            authProperties.RedirectUri = result.Location.OriginalString;

            return new MultipleIdentityAuthenticationTicket(identities, authProperties);
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, AuthenticationMode.Passive);

                if (challenge != null)
                {
                    EntityId idp;
                    string strIdp;
                    if (challenge.Properties.Dictionary.TryGetValue("idp", out strIdp))
                    {
                        idp = new EntityId(strIdp);
                    }
                    else
                    {
                        object objIdp = null;
                        Context.Environment.TryGetValue("KentorAuthServices.idp", out objIdp);
                        idp = objIdp as EntityId;
                    }


                    var result = CreateResult (
                        idp,
                        challenge.Properties.RedirectUri,
                        await Context.ToHttpRequestData(),
                        Options,
                        challenge.Properties);

                    result.Apply(Context);
                }
            }
        }

        public override async Task<bool> InvokeAsync()
        {
            var authServicesPath = new PathString(Options.SPOptions.ModulePath);
            PathString remainingPath;
            
            if (Request.Path.StartsWithSegments(authServicesPath, out remainingPath))
            {
                if (remainingPath == new PathString("/" + CommandFactory.AcsCommandName))
                {

                    await AuthorizeAsync();

                    return true;
                }

                CommandFactory.GetCommand(remainingPath.Value)
                    .Run(await Context.ToHttpRequestData(), Options)
                    .Apply(Context);

                return true;
            }

            return false;
        }

        protected abstract Task AuthorizeAsync();

        static CommandResult CreateResult(
            EntityId idpEntityId,
            string returnPath,
            HttpRequestData request,
            IOptions options,
            object relayData = null)
        {
            var urls = new AuthServicesUrls(request, options.SPOptions);

            IdentityProvider idp;
            if (idpEntityId == null || idpEntityId.Id == null)
            {
                //if (options.SPOptions.DiscoveryServiceUrl != null)
                //{
                //    return RedirectToDiscoveryService(returnPath, options.SPOptions, urls);
                //}

                idp = options.IdentityProviders.Default;
            }
            else
            {
                if (!options.IdentityProviders.TryGetValue(idpEntityId, out idp))
                {
                    throw new InvalidOperationException("Unknown idp");
                }
            }

            Uri returnUrl = null;
            if (!string.IsNullOrEmpty(returnPath))
            {
                Uri.TryCreate(request.Url, returnPath, out returnUrl);
            }

            var authnRequest = idp.CreateAuthenticateRequest(returnUrl, urls, relayData);

            return idp.Bind(authnRequest);
        }
    }

}
