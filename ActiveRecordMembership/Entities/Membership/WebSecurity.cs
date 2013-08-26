using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using ActiveRecordMembership.Context;

namespace ActiveRecordMembership.Entities.Membership
{
    public sealed class WebSecurity
    {
        public static HttpContextBase Context
        {
            get { return new HttpContextWrapper(HttpContext.Current); }
        }

        public static HttpRequestBase Request
        {
            get { return Context.Request; }
        }

        public static HttpResponseBase Response
        {
            get { return Context.Response; }
        }

        public static System.Security.Principal.IPrincipal User
        {
            get { return Context.User; }
        }

        public static bool IsAuthenticated
        {
            get { return User.Identity.IsAuthenticated; }
        }
        public static SecurityUser CurrentUser()
        {
            return UserContext.Current.CurrentSecurityUser;
        }
        public static bool HasRole(string roleName)
        {
            return (UserContext.Current.CurrentSecurityUser.SecurityRole.RoleName.Trim().ToUpper() == roleName.Trim().ToUpper());
        }
        public static bool IsSecuritySettingAtLeast(string areaName, SecurityLevelEnum minimumLevel)
        {
            return UserContext.Current.CurrentSecurityUser.SecuritySettingAtLeast(UserContext.Current,areaName,minimumLevel);
        }
        public static MembershipCreateStatus Register(string Username, string Password, string Email, bool IsApproved, string FirstName, string LastName)
        {
            MembershipCreateStatus CreateStatus;
            System.Web.Security.Membership.CreateUser(Username, Password, Email, null, null, IsApproved, null, out CreateStatus);

            if (CreateStatus == MembershipCreateStatus.Success)
            {
                var dbContext = UserContext.Current;
                {
                    SecurityUser securityUser = dbContext.Users.FirstOrDefault(Usr => Usr.Username == Username);
                    securityUser.FirstName = FirstName;
                    securityUser.LastName = LastName;
                    dbContext.SaveChanges();
                }

                //if (IsApproved)
                //{
                //    try
                //    {
                //        FormsAuthentication.SetAuthCookie(Username, false);
                //    }
                //    catch (Exception)
                //    {
                        
                //    }
                //}
            }

            return CreateStatus;
        }

        public enum MembershipLoginStatus
        {
            Success, Failure
        }
        public static void ClearAuthCookie()
        {
            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, "");
            cookie.HttpOnly = true;
            cookie.Path = HttpContext.Current.Request.ApplicationPath;
            cookie.Secure = string.Equals("https", HttpContext.Current.Request.Url.Scheme, StringComparison.OrdinalIgnoreCase);
            // the browser will ignore the cookie if there are fewer than two dots
            // see cookie spec - http://curl.haxx.se/rfc/cookie_spec.html
            if (HttpContext.Current.Request.Url.Host.Split('.').Length > 2)
            {
                // by default the domain will be the host, so www.site.com will get site.com
                // this may be a problem if we have clientA.site.com and clientB.site.com
                // the following line will force the full domain name
                cookie.Domain = HttpContext.Current.Request.Url.Host;
            }

            cookie.Expires = DateTime.Now.AddYears(-1);
            Response.Cookies.Add(cookie);
        }
        public static void SetAuthCookie(string username, bool rememberMe)
        {
            // replacement for FormsAuthentication.SetAuthCookie(user.UserName, false);
            // as that fails to limit the cookie by domain & path and fails.

            var cookie = FormsAuthentication.GetAuthCookie(username, false);
            cookie.HttpOnly = true;
            cookie.Path = HttpContext.Current.Request.ApplicationPath;
            cookie.Secure = string.Equals("https", HttpContext.Current.Request.Url.Scheme, StringComparison.OrdinalIgnoreCase);

            // the browser will ignore the cookie if there are fewer than two dots
            // see cookie spec - http://curl.haxx.se/rfc/cookie_spec.html
            if (HttpContext.Current.Request.Url.Host.Split('.').Length > 2)
            {
                // by default the domain will be the host, so www.site.com will get site.com
                // this may be a problem if we have clientA.site.com and clientB.site.com
                // the following line will force the full domain name
                cookie.Domain = HttpContext.Current.Request.Url.Host;
            }

            HttpContext.Current.Response.Cookies.Add(cookie);
        }

        public static MembershipLoginStatus Login(string Username, string Password, bool RememberMe)
        {
            UserContext.Current.CurrentSecurityUser = null;
            if (System.Web.Security.Membership.ValidateUser(Username, Password))
            {
                SetAuthCookie(Username, RememberMe);
                //FormsAuthentication.SetAuthCookie(Username, RememberMe);

                var u = SecurityUser.LoadByName(UserContext.Current, Username);
                u.AddTrackingEvent(DateTime.Now, TrackType.LoggedIn, Request.UserHostAddress);
                u.LastActivityDate = DateTime.Now;
                u.Save(UserContext.Current);
                return MembershipLoginStatus.Success;
            }
            else
            {
                return MembershipLoginStatus.Failure;
            }
        }
        

        public static void Logout()
        {
            if (CurrentUser() != null && CurrentUser().Id!=0)
            {
                try
                {
                    var u = SecurityUser.Load(UserContext.Current, CurrentUser().Id);
                    u.AddTrackingEvent(DateTime.Now, TrackType.LoggedOut, Request.UserHostAddress);
                    u.LastActivityDate = DateTime.Now;
                    u.Save(UserContext.Current);
                }
                catch (Exception)
                {
                    
                }
            }
            FormsAuthentication.SignOut();
            ClearAuthCookie();
            UserContext.Current.CurrentSecurityUser = null;
        }

        public static MembershipUser GetUser(string Username)
        {
            return System.Web.Security.Membership.GetUser(Username);
        }

        public static bool ChangePassword(string OldPassword, string NewPassword)
        {
            MembershipUser CurrentUser = System.Web.Security.Membership.GetUser(User.Identity.Name);
            return CurrentUser.ChangePassword(OldPassword, NewPassword);
        }

        public static bool DeleteUser(string Username)
        {
            return System.Web.Security.Membership.DeleteUser(Username);
        }

        public static List<MembershipUser> FindUsersByEmail(string Email, int PageIndex, int PageSize)
        {
            int totalRecords;
            return System.Web.Security.Membership.FindUsersByEmail(Email, PageIndex, PageSize, out totalRecords).Cast<MembershipUser>().ToList();
        }

        public static List<MembershipUser> FindUsersByName(string Username, int PageIndex, int PageSize)
        {
            int totalRecords;
            return System.Web.Security.Membership.FindUsersByName(Username, PageIndex, PageSize, out totalRecords).Cast<MembershipUser>().ToList();
        }

        public static List<MembershipUser> GetAllUsers(int PageIndex, int PageSize)
        {
            int totalRecords;
            return System.Web.Security.Membership.GetAllUsers(PageIndex, PageSize, out totalRecords).Cast<MembershipUser>().ToList();
        }
    }
}