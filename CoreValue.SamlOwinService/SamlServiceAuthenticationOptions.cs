using Kentor.AuthServices.Configuration;
using Microsoft.Owin.Security;

namespace CoreValue.SamlOwinService
{
    public class SamlServiceAuthenticationOptions : AuthenticationOptions, IOptions
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204:Literals should be spelled correctly", MessageId = "KentorAuthServices")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Globalization", "CA1303:Do not pass literals as localized parameters", MessageId = "Microsoft.Owin.Security.AuthenticationDescription.set_Caption(System.String)")]
        public SamlServiceAuthenticationOptions(bool loadConfiguration)
            : base(Constants.DefaultAuthenticationType)
        {
            AuthenticationMode = AuthenticationMode.Passive;
            Description.Caption = Constants.DefaultCaption;

            if (loadConfiguration)
            {
                SPOptions = new SPOptions(KentorAuthServicesSection.Current);
                KentorAuthServicesSection.Current.IdentityProviders.RegisterIdentityProviders(this);
                KentorAuthServicesSection.Current.Federations.RegisterFederations(this);
            }
        }

        public string SignInAsAuthenticationType { get; set; }

        //
        public string TokenUrl { get; set; }

        public ISPOptions SPOptions { get; set; }

        private readonly IdentityProviderDictionary identityProviders = new IdentityProviderDictionary();

        public IdentityProviderDictionary IdentityProviders
        {
            get
            {
                return identityProviders;
            }
        }

        public string Caption
        {
            get
            {
                return Description.Caption;
            }
            set
            {
                Description.Caption = value;
            }
        }
    }
}
