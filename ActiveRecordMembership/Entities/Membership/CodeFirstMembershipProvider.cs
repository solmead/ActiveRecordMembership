using System;
using System.Linq;
using System.Text;
using System.Web.Security;
using ActiveRecordMembership.Context;
using ActiveRecordMembership.Properties;

namespace ActiveRecordMembership.Entities.Membership
{
    public class CodeFirstMembershipProvider : MembershipProvider
    {

        #region Properties

        public override string ApplicationName
        {
            get
            {
                return this.GetType().Assembly.GetName().Name.ToString();
            }
            set
            {
                this.ApplicationName = this.GetType().Assembly.GetName().Name.ToString();
            }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return Settings.Default.MaxInvalidPasswordAttempts; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return Settings.Default.MinRequiredNonAlphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return Settings.Default.MinRequiredPasswordLength; }
        }

        public override int PasswordAttemptWindow
        {
            get { return Settings.Default.PasswordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return Settings.Default.PasswordFormat; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return Settings.Default.PasswordStrengthRegularExpression; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return Settings.Default.RequiresUniqueEmail; }
        }

        #endregion

        #region Functions

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            if (string.IsNullOrEmpty(username))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }
            if (string.IsNullOrEmpty(password))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            if (string.IsNullOrEmpty(email))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            string HashedPassword = Crypto.HashPassword(password);
            if (HashedPassword.Length > 128)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            var Context = UserContext.Current;
            {
                if (Context.Users.Where(Usr => Usr.Username == username).Any())
                {
                    status = MembershipCreateStatus.DuplicateUserName;
                    return null;
                }

                //if (Context.Users.Where(Usr => Usr.Email == email).Any())
                //{
                //    status = MembershipCreateStatus.DuplicateEmail;
                //    return null;
                //}
                var newSecurityUser = SecurityUser.CreateUser(username, password, email, null, isApproved);
                //SecurityUser newSecurityUser = new SecurityUser
                //{
                //    //UserId = Guid.NewGuid(),
                //    Username = username,
                //    EncryptedPassword = HashedPassword,
                //    Enabled = isApproved,
                //    Email = email,
                //    CreateDate = DateTime.Now,
                //    LastPasswordChangedDate = DateTime.Now,
                //    PasswordFailuresSinceLastSuccess = 0,
                //    LastLoginDate = DateTime.Now,
                //    LastActivityDate = DateTime.Now,
                //    LastLockoutDate = DateTime.Now,
                //    IsLockedOut = false,
                //    LastPasswordFailureDate = DateTime.Now
                //};

                Context.Users.Add(newSecurityUser);
                Context.SaveChanges();
                status = MembershipCreateStatus.Success;
                return new MembershipUser(System.Web.Security.Membership.Provider.Name, newSecurityUser.Username, newSecurityUser.Id, newSecurityUser.Email, null, null, newSecurityUser.Enabled, newSecurityUser.IsLockedOut, newSecurityUser.CreateDate.GetValue(), newSecurityUser.LastLoginDate.GetValue(), newSecurityUser.LastActivityDate.GetValue(), newSecurityUser.LastPasswordChangedDate.GetValue(), newSecurityUser.LastLockoutDate.GetValue());
            }
        }

        public override bool ValidateUser(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }
            if (string.IsNullOrEmpty(password))
            {
                return false;
            }
            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == username);
                if (securityUser == null)
                {
                    return false;
                }
                if (!securityUser.Enabled)
                {
                    return false;
                }
                if (securityUser.IsLockedOut)
                {
                    return false;
                }
                String HashedPassword = securityUser.EncryptedPassword;
                Boolean VerificationSucceeded = false;
                if (String.IsNullOrWhiteSpace(securityUser.OldSalt))
                {
                    VerificationSucceeded = (HashedPassword != null &&
                                                     Crypto.VerifyHashedPassword(HashedPassword, password));
                }
                else
                {
                    var SHa = new System.Security.Cryptography.SHA512Managed();
                    var TPass = Convert.ToBase64String(SHa.ComputeHash(Encoding.UTF8.GetBytes(password + ":" + securityUser.OldSalt)));
                    VerificationSucceeded = (HashedPassword != null && (HashedPassword == TPass));
                }
                if (VerificationSucceeded)
                {
                    securityUser.PasswordFailuresSinceLastSuccess = 0;
                    securityUser.LastLoginDate = DateTime.Now;
                    securityUser.LastActivityDate = DateTime.Now;
                }
                else
                {
                    int Failures = securityUser.PasswordFailuresSinceLastSuccess;
                    if (Failures < MaxInvalidPasswordAttempts)
                    {
                        securityUser.PasswordFailuresSinceLastSuccess += 1;
                        securityUser.LastPasswordFailureDate = DateTime.Now;
                    }
                    else if (Failures >= MaxInvalidPasswordAttempts)
                    {
                        securityUser.LastPasswordFailureDate = DateTime.Now;
                        securityUser.LastLockoutDate = DateTime.Now;
                        securityUser.IsLockedOut = true;
                        //throw new Exception("Please try using the forgot password feature.");
                    }
                }
                
                Context.SaveChanges();
                if (VerificationSucceeded)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (string.IsNullOrEmpty(username))
            {
                return null;
            }
            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == username);
                if (securityUser != null)
                {
                    if (userIsOnline)
                    {
                        securityUser.LastActivityDate = DateTime.Now;
                        Context.SaveChanges();
                    }
                    return new MembershipUser(System.Web.Security.Membership.Provider.Name, securityUser.Username, securityUser.Id, securityUser.Email, null, null, securityUser.Enabled, securityUser.IsLockedOut, securityUser.CreateDate.GetValue(), securityUser.LastLoginDate.GetValue(), securityUser.LastActivityDate.GetValue(), securityUser.LastPasswordChangedDate.GetValue(), securityUser.LastLockoutDate.GetValue());
                }
                else
                {
                    return null;
                }
            }
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (providerUserKey is Guid) { }
            else
            {
                return null;
            }

            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.Find(providerUserKey);
                if (securityUser != null)
                {
                    if (userIsOnline)
                    {
                        securityUser.LastActivityDate = DateTime.Now;
                        Context.SaveChanges();
                    }
                    return new MembershipUser(System.Web.Security.Membership.Provider.Name, securityUser.Username, securityUser.Id, securityUser.Email, null, null, securityUser.Enabled, securityUser.IsLockedOut, securityUser.CreateDate.GetValue(), securityUser.LastLoginDate.GetValue(), securityUser.LastActivityDate.GetValue(), securityUser.LastPasswordChangedDate.GetValue(), securityUser.LastLockoutDate.GetValue());
                }
                else
                {
                    return null;
                }
            }
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }
            if (string.IsNullOrEmpty(oldPassword))
            {
                return false;
            }
            if (string.IsNullOrEmpty(newPassword))
            {
                return false;
            }
            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == username);
                if (securityUser == null)
                {
                    return false;
                }
                String HashedPassword = securityUser.EncryptedPassword;
                Boolean VerificationSucceeded = (HashedPassword != null && Crypto.VerifyHashedPassword(HashedPassword, oldPassword));
                if (VerificationSucceeded)
                {
                    securityUser.PasswordFailuresSinceLastSuccess = 0;
                }
                else
                {
                    int Failures = securityUser.PasswordFailuresSinceLastSuccess;
                    if (Failures < MaxInvalidPasswordAttempts)
                    {
                        securityUser.PasswordFailuresSinceLastSuccess += 1;
                        securityUser.LastPasswordFailureDate = DateTime.Now;
                    }
                    else if (Failures >= MaxInvalidPasswordAttempts)
                    {
                        securityUser.LastPasswordFailureDate = DateTime.Now;
                        securityUser.LastLockoutDate = DateTime.Now;
                        securityUser.IsLockedOut = true;
                    }
                    Context.SaveChanges();
                    return false;
                }
                String NewHashedPassword = Crypto.HashPassword(newPassword);
                if (NewHashedPassword.Length > 128)
                {
                    return false;
                }
                securityUser.EncryptedPassword = NewHashedPassword;
                securityUser.OldSalt = "";
                securityUser.LastPasswordChangedDate = DateTime.Now;
                Context.SaveChanges();
                return true;
            }
        }

        public override bool UnlockUser(string userName)
        {
            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == userName);
                if (securityUser != null)
                {
                    securityUser.IsLockedOut = false;
                    securityUser.PasswordFailuresSinceLastSuccess = 0;
                    Context.SaveChanges();
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public override int GetNumberOfUsersOnline()
        {
            DateTime DateActive = DateTime.Now.Subtract(TimeSpan.FromMinutes(Convert.ToDouble(System.Web.Security.Membership.UserIsOnlineTimeWindow)));
            
            var Context = UserContext.Current;
            {
                return Context.Users.Where(Usr => Usr.LastActivityDate > DateActive).Count();
            }
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }
            var Context = UserContext.Current;
            SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == username);
                if (securityUser != null)
                {
                    Context.Users.Remove(securityUser);
                    Context.SaveChanges();
                    return true;
                }
                else
                {
                    return false;
                }
        }

        public override string GetUserNameByEmail(string email)
        {
            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Email == email);
                if (securityUser != null)
                {
                    return securityUser.Username;
                }
                else
                {
                    return string.Empty;
                }
            }
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection MembershipUsers = new MembershipUserCollection();
            var Context = UserContext.Current;
            {
                totalRecords = Context.Users.Where(Usr => Usr.Email == emailToMatch).Count();
                IQueryable<SecurityUser> Users = Context.Users.Where(Usr => Usr.Email == emailToMatch).OrderBy(Usrn => Usrn.Username).Skip(pageIndex * pageSize).Take(pageSize);
                foreach (SecurityUser user in Users)
                {
                    MembershipUsers.Add(new MembershipUser(System.Web.Security.Membership.Provider.Name, user.Username, user.Id, user.Email, null, null, user.Enabled, user.IsLockedOut, user.CreateDate.GetValue(), user.LastLoginDate.GetValue(), user.LastActivityDate.GetValue(), user.LastPasswordChangedDate.GetValue(), user.LastLockoutDate.GetValue()));
                }
            }
            return MembershipUsers;
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection MembershipUsers = new MembershipUserCollection();
            var Context = UserContext.Current;
            {
                totalRecords = Context.Users.Where(Usr => Usr.Username == usernameToMatch).Count();
                IQueryable<SecurityUser> Users = Context.Users.Where(Usr => Usr.Username == usernameToMatch).OrderBy(Usrn => Usrn.Username).Skip(pageIndex * pageSize).Take(pageSize);
                foreach (SecurityUser user in Users)
                {
                    MembershipUsers.Add(new MembershipUser(System.Web.Security.Membership.Provider.Name, user.Username, user.Id, user.Email, null, null, user.Enabled, user.IsLockedOut, user.CreateDate.GetValue(), user.LastLoginDate.GetValue(), user.LastActivityDate.GetValue(), user.LastPasswordChangedDate.GetValue(), user.LastLockoutDate.GetValue()));
                }
            }
            return MembershipUsers;
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection MembershipUsers = new MembershipUserCollection();
            var Context = UserContext.Current;
            {
                totalRecords = Context.Users.Count();
                IQueryable<SecurityUser> Users = Context.Users.OrderBy(Usrn => Usrn.Username).Skip(pageIndex * pageSize).Take(pageSize);
                foreach (SecurityUser user in Users)
                {
                    MembershipUsers.Add(new MembershipUser(System.Web.Security.Membership.Provider.Name, user.Username, user.Id, user.Email, null, null, user.Enabled, user.IsLockedOut, user.CreateDate.GetValue(), user.LastLoginDate.GetValue(), user.LastActivityDate.GetValue(), user.LastPasswordChangedDate.GetValue(), user.LastLockoutDate.GetValue()));
                }
            }
            return MembershipUsers;
        }

        #endregion

        #region Not Supported

        //CodeFirstMembershipProvider does not support password retrieval scenarios.
        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }
        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException("Consider using methods from WebSecurity module.");
        }

        //CodeFirstMembershipProvider does not support password reset scenarios.
        public override bool EnablePasswordReset
        {
            get { return true; }
        }
        public override string ResetPassword(string username, string answer)
        {
            var newPassword = Guid.NewGuid().ToString().Substring(0,8);
            if (string.IsNullOrEmpty(username))
            {
                throw new Exception("username required");
            }

            var Context = UserContext.Current;
            {
                SecurityUser securityUser = null;
                securityUser = Context.Users.FirstOrDefault(Usr => Usr.Username == username);
                if (securityUser == null)
                {
                    throw new Exception("user required");
                }
                
                String NewHashedPassword = Crypto.HashPassword(newPassword);
                securityUser.EncryptedPassword = NewHashedPassword;
                securityUser.OldSalt = "";
                securityUser.LastPasswordChangedDate = DateTime.Now;
                Context.SaveChanges();
                return newPassword;
            }
        }

        //CodeFirstMembershipProvider does not support question and answer scenarios.
        public override bool RequiresQuestionAndAnswer
        {
            get { return false; }
        }
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException("Consider using methods from WebSecurity module.");
        }

        //CodeFirstMembershipProvider does not support UpdateUser because this method is useless.
        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }

        #endregion
    }
}