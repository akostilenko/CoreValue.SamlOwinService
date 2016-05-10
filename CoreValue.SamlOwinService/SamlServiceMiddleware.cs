using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace CoreValue.SamlOwinService
{
    /// <summary>
    /// Owin middleware for SAML2 authentication.
    /// </summary>
    public class SamlServiceMiddleware<T>
        : AuthenticationMiddleware<SamlServiceAuthenticationOptions> where T : SamlServiceHandler, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="app">The app that this middleware will be registered with.</param>
        /// <param name="options">Settings for the middleware.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1062:Validate arguments of public methods", MessageId = "2", Justification="options is validated by base ctor. Test case for null options giving ArgumentNullException works.")]
        public SamlServiceMiddleware(OwinMiddleware next, IAppBuilder app,
            SamlServiceAuthenticationOptions options)
            :base (next, options)
        {
            if(app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if(string.IsNullOrEmpty(options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
        }

        /// <summary>
        /// Creates a handler instance for use when processing a request.
        /// </summary>
        /// <returns>Handler instance.</returns>
        protected override AuthenticationHandler<SamlServiceAuthenticationOptions> CreateHandler()
        {
            return new T();
        }
    }
}
