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

        public static MembershipLoginStatus Login(string Username, string Password, bool RememberMe)
        {
            UserContext.Current.CurrentSecurityUser = null;
            if (System.Web.Security.Membership.ValidateUser(Username, Password))
            {
                FormsAuthentication.SetAuthCookie(Username, RememberMe);

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
            var u = SecurityUser.Load(UserContext.Current, CurrentUser().Id);
            u.AddTrackingEvent(DateTime.Now, TrackType.LoggedOut, Request.UserHostAddress);
            u.LastActivityDate = DateTime.Now;
            u.Save(UserContext.Current);
            FormsAuthentication.SignOut();
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