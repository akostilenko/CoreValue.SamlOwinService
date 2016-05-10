using System.Threading.Tasks;
using Kentor.AuthServices.WebSso;
using Microsoft.Owin;

namespace CoreValue.SamlOwinService
{
    static class OwinContextExtensions
    {
        public async static Task<HttpRequestData> ToHttpRequestData(this IOwinContext context)
        {
            if(context == null)
            {
                return null;
            }

            IFormCollection formData = null;
            if(context.Request.Body != null)
            {
                formData = await context.Request.ReadFormAsync();
            }

            var applicationRootPath = context.Request.PathBase.Value;
            if(string.IsNullOrEmpty(applicationRootPath))
            {
                applicationRootPath = "/";
            }
            return new HttpRequestData(
                context.Request.Method,
                context.Request.Uri,
                applicationRootPath,
                formData);
        }
    }
}
