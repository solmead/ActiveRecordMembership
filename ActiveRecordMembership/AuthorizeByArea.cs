using System;
using System.Web;
using System.Web.Mvc;
using ActiveRecordMembership.Context;
using ActiveRecordMembership.Entities;

namespace ActiveRecordMembership
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = true)]
    public class AuthorizeByArea : AuthorizeAttribute
    {
        public AuthorizeByArea()
            : base()
        {
            MinimumLevel = SecurityLevelEnum.Delete;
            Area = "Users";
            if (Roles == "")
            {
                Roles = "noneshallpass";
            }
        }

        public string Area { get; set; }
        public SecurityLevelEnum MinimumLevel { get; set; }
        public string RedirectURL { get; set; }
        public bool RedirectToPrevious { get; set; }

        protected void CacheValidateHandler(HttpContext context, Object data, ref HttpValidationStatus validationStatus)
        {
            validationStatus = OnCacheAuthorization(new HttpContextWrapper(context));
        }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            //base.OnAuthorization(filterContext);

            if (filterContext == null)
            {
                throw new ArgumentException("filtercontext");
            }
            //var baseController = filterContext.Controller as CMSBaseController;
            var context = UserContext.Current;

            if (AuthorizeCore(filterContext.HttpContext))
            {
                SetCachePolicy(filterContext);
            }
            else if (!filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                filterContext.Result = new HttpUnauthorizedResult();
            }
            else if (context.CurrentSecurityUser.SecuritySettingAtLeast(context,Area, MinimumLevel))
            {
                SetCachePolicy(filterContext);
            }
            else
            {
                if (RedirectToPrevious && filterContext.HttpContext.Request.UrlReferrer != null)
                {
                    filterContext.Result = 
                        new RedirectResult(filterContext.HttpContext.Request.UrlReferrer.OriginalString);
                }
                else if (string.IsNullOrWhiteSpace(RedirectURL))
                {
                    filterContext.Result = new HttpUnauthorizedResult();
                }
                else
                {
                    filterContext.Result = new RedirectResult(RedirectURL);
                }
            }

        }

        protected void SetCachePolicy(AuthorizationContext filterContext)
        {

            // ** IMPORTANT **
            // Since we're performing authorization at the action level, the authorization code runs
            // after the output caching module. In the worst case this could allow an authorized user
            // to cause the page to be cached, then an unauthorized user would later be served the
            // cached page. We work around this by telling proxies not to cache the sensitive page,
            // then we hook our custom authorization code into the caching mechanism so that we have
            // the final say on whether a page should be served from the cache.
            var cachePolicy = filterContext.HttpContext.Response.Cache;
            cachePolicy.SetProxyMaxAge(new TimeSpan(0));
            cachePolicy.AddValidationCallback(CacheValidateHandler, null);
        }

    }
}
