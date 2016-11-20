using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace MSAcountLogin
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static PublicClientApplication ClientApplication { get; set; }
        public static string[] Scopes = { "User.Read" };
        public IPlatformParameters PlatformParameters { get; set; }


        public MainWindow()
        {
            InitializeComponent();
        }

        private static async Task AcquireTokenAsync()
        {
            TokenBroker app = new TokenBroker();
            string token = await GetTokenIntegratedAuthAsync(app.Sts).ConfigureAwait(false);
            Console.WriteLine(token);
        }


        public static async Task<AuthenticationResult> GetTokenSilentAsync(User user)
        {
            TokenBroker brkr = new TokenBroker();
            PublicClientApplication app =
                new PublicClientApplication("269da09d-a3e8-4b9e-b0a3-18fdf67d7507");
            try
            {
                return await app.AcquireTokenSilentAsync(brkr.Sts.ValidScope);
            }
            catch (Exception ex)
            {
                string msg = ex.Message + "\n" + ex.StackTrace;
                Console.WriteLine(msg);
                return await app.AcquireTokenAsync(brkr.Sts.ValidScope, user.DisplayableId, UiOptions.ActAsCurrentUser, null);
            }

        }

        public static async Task<AuthenticationResult> GetTokenInteractiveAsync()
        {
            try
            {
                TokenBroker brkr = new TokenBroker();
                PublicClientApplication app =
                    new PublicClientApplication("269da09d-a3e8-4b9e-b0a3-18fdf67d7507");
                await app.AcquireTokenAsync(brkr.Sts.ValidScope);

                return await app.AcquireTokenAsync(brkr.Sts.ValidScope);
            }
            catch (Exception ex)
            {
                string msg = ex.Message + "\n" + ex.StackTrace;
                Console.WriteLine(msg);
            }

            return null;
        }

        public static async Task<string> GetTokenIntegratedAuthAsync(Sts Sts)
        {
            try
            {
                PublicClientApplication app = new PublicClientApplication(Sts.Authority, "269da09d-a3e8-4b9e-b0a3-18fdf67d7507");
                var result = await app.AcquireTokenWithIntegratedAuthAsync(Sts.ValidScope);
                return result.Token;
            }
            catch (Exception ex)
            {
                string msg = ex.Message + "\n" + ex.StackTrace;

                return msg;
            }
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var task = GetTokenInteractiveAsync();
                Task.WaitAll(task);
                var result = task.Result;
                Console.WriteLine(result.Token);

                task = GetTokenSilentAsync(result.User);
                Task.WaitAll(task);
                result = task.Result;

                Console.WriteLine(result.Token);
            }
            catch (AggregateException ae)
            {
                Console.WriteLine(ae.InnerException.Message);
                Console.WriteLine(ae.InnerException.StackTrace);
            }
            finally
            {
                Console.ReadKey();
            }
        }
    }


    public class TokenBroker
    {
        private PublicClientApplication app;
        public Sts Sts = new MobileAppSts();

        public async Task<string> GetTokenSilentAsync(IPlatformParameters parameters)
        {
            try
            {
                app = new PublicClientApplication("https://login.windows.net/common", "269da09d-a3e8-4b9e-b0a3-18fdf67d7507");
                var result = await app.AcquireTokenSilentAsync(Sts.ValidScope, Sts.ValidUserName);

                return result.Token;
            }
            catch (Exception ex)
            {
                string msg = ex.Message + "\n" + ex.StackTrace;

                return msg;
            }
        }


        public string GetTokenInteractiveWithMsAppAsync(IPlatformParameters parameters)
        {
            try
            {
                /* app = new AuthenticationContext(Sts.Authority, true);
                                                var result = await app.AcquireTokenAsync(Sts.ValidScope, Sts.ValidClientId, null, parameters, new UserIdentifier(Sts.ValidUserName, UserIdentifierType.OptionalDisplayableId));

                                                return result.Token;*/
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }


        public string GetTokenWithClientCredentialAsync()
        {
            try
            {
                /* app = new AuthenticationContext(Sts.Authority, true);
                                                var result = await app.AcquireTokenAsync(Sts.ValidScope, new ClientCredential(Sts.ValidConfidentialClientId, Sts.ValidConfidentialClientSecret));

                                                return result.Token;*/
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public void ClearTokenCache()
        {
            TokenCache.DefaultSharedUserTokenCache.Clear("CLIENT_ID");
        }
    }

    public class MobileAppSts : Sts
    {
        public MobileAppSts()
        {
            this.InvalidAuthority = "https://invalid_address.com/path";
            this.ValidateAuthority = true;
            this.ValidExistingRedirectUri = new Uri("https://login.live.com/");
            this.ValidExpiresIn = 28800;
            this.ValidNonExistingRedirectUri = new Uri("urn:ietf:wg:oauth:2.0:oob");
            this.ValidLoggedInFederatedUserName = "dummy\\dummy";
            string[] segments = this.ValidLoggedInFederatedUserName.Split(new[] { '\\' });
            this.ValidLoggedInFederatedUserId = string.Format(CultureInfo.InvariantCulture, "{0}@microsoft.com", (segments.Length == 2) ? segments[1] : segments[0]);
            this.TenantName = "Common";
            this.Authority = string.Format(CultureInfo.InvariantCulture, "https://login.windows.net/{0}", this.TenantName);
            this.TenantlessAuthority = "https://login.windows.net/Common";
            this.ValidClientId = "dd9caee2-38bd-484e-998c-7529bdef220f";
            this.ValidNonExistentRedirectUriClientId = this.ValidClientId;
            this.ValidClientIdWithExistingRedirectUri = this.ValidClientId;
            this.ValidUserName = @"<REPLACE>";
            this.ValidDefaultRedirectUri = new Uri("https://login.live.com/");
            this.ValidExistingRedirectUri = new Uri("https://login.live.com/");
            this.ValidRedirectUriForConfidentialClient = new Uri("https://confidential.clientredirecturi.com");
            this.ValidPassword = "<REPLACE>";
            this.ValidScope = new[] { "https://graph.microsoft.com/user.read" };

        }

        public string TenantName { get; protected set; }
    }
    public class Sts
    {
        public const string InvalidArgumentError = "invalid_argument";
        public const string InvalidRequest = "invalid_request";
        public const string InvalidResourceError = "invalid_resource";
        public const string InvalidClientError = "invalid_client";
        public const string AuthenticationFailedError = "authentication_failed";
        public const string AuthenticationUiFailedError = "authentication_ui_failed";
        public const string AuthenticationCanceledError = "authentication_canceled";
        public const string AuthorityNotInValidList = "authority_not_in_valid_list";
        public const string InvalidAuthorityType = "invalid_authority_type";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string UserInteractionRequired = "user_interaction_required";

        public Sts()
        {
            this.ValidDefaultRedirectUri = new Uri("https://non_existing_uri.com/");
            this.InvalidExistingRedirectUri = new Uri("https://skydrive.live.com/");
            this.InvalidNonExistingRedirectUri = new Uri("https://invalid_non_existing_uri.com/");
            this.ConfidentialClientCertificateName = "valid_cert.pfx";
            this.InvalidConfidentialClientCertificateName = "invalid_cert.pfx";
            this.ConfidentialClientCertificatePassword = "password";
            this.InvalidConfidentialClientCertificatePassword = "password";
        }

        public bool ValidateAuthority { get; protected set; }

        public string Authority { get; set; }

        public string TenantlessAuthority { get; protected set; }

        public string[] ValidScope { get; set; }

        public string[] ValidScope2 { get; protected set; }

        public string ValidClientId { get; set; }

        public string ValidClientIdWithExistingRedirectUri { get; protected set; }

        public string ValidConfidentialClientId { get; set; }

        public string ValidConfidentialClientSecret { get; set; }

        public string ValidWinRTClientId { get; protected set; }

        public long ValidExpiresIn { get; protected set; }

        public Uri ValidExistingRedirectUri { get; set; }

        public string ValidLoggedInFederatedUserId { get; protected set; }

        public string ValidLoggedInFederatedUserName { get; protected set; }

        public Uri ValidNonExistingRedirectUri { get; set; }

        public Uri ValidDefaultRedirectUri { get; set; }

        public Uri ValidRedirectUriForConfidentialClient { get; set; }

        public string ValidUserName { get; set; }

        public string ValidUserName2 { get; protected set; }

        public string ValidUserName3 { get; protected set; }

        public string ValidPassword { get; set; }

        public string ValidPassword2 { get; set; }

        public string ValidPassword3 { get; set; }

        public string InvalidResource { get; protected set; }

        public string InvalidClientId { get; protected set; }

        public string InvalidAuthority { get; protected set; }

        public Uri InvalidExistingRedirectUri { get; set; }

        public Uri InvalidNonExistingRedirectUri { get; set; }

        public string ConfidentialClientCertificateName { get; set; }

        public string InvalidConfidentialClientCertificateName { get; set; }

        public string ConfidentialClientCertificatePassword { get; set; }

        public string InvalidConfidentialClientCertificatePassword { get; set; }

        public string InvalidUserName
        {
            get { return this.ValidUserName + "x"; }
        }

        public string ValidNonExistentRedirectUriClientId { get; set; }

        public string MsaUserName { get; protected set; }
        public string MsaPassword { get; protected set; }
    }
}
