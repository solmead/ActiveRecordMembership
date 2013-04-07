using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Security;
using ActiveRecordMembership.Context;

namespace ActiveRecordMembership.Entities.Membership
{
    public class CodeFirstRoleProvider : RoleProvider
    {
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

        public override bool RoleExists(string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return false;
            }
            var Context = UserContext.Current;
            {
                SecurityRole SecurityRole = null;
                SecurityRole = Context.Roles.FirstOrDefault(Rl => Rl.RoleName == roleName);
                if (SecurityRole != null)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }
            if (string.IsNullOrEmpty(roleName))
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
                SecurityRole SecurityRole = Context.Roles.FirstOrDefault(Rl => Rl.RoleName == roleName);
                if (SecurityRole == null)
                {
                    return false;
                }
                return (securityUser.SecurityRole == SecurityRole);
            }
        }

        public override string[] GetAllRoles()
        {
            var Context = UserContext.Current;
            {
                return Context.Roles.Select(Rl => Rl.RoleName).ToArray();
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return null;
            }
            var Context = UserContext.Current;
            {
                SecurityRole SecurityRole = null;
                SecurityRole = Context.Roles.FirstOrDefault(Rl => Rl.RoleName == roleName);
                if (SecurityRole != null)
                {
                    return SecurityRole.Users.Select(Usr => Usr.Username).ToArray();
                }
                else
                {
                    return null;
                }
            }
        }

        public override string[] GetRolesForUser(string username)
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
                    return new string[] {securityUser.SecurityRole.RoleName};
                }
                else
                {
                    return null;
                }
            }
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return null;
            }

            if (string.IsNullOrEmpty(usernameToMatch))
            {
                return null;
            }

            var Context = UserContext.Current;
            {

                return (from Rl in Context.Roles 
                        where Rl.RoleName == roleName 
                        from Usr in Rl.Users 
                        where Usr.Username.Contains(usernameToMatch) 
                        select Usr.Username).ToArray();
            }
        }

        public override void CreateRole(string roleName)
        {
            if (!string.IsNullOrEmpty(roleName))
            {
                var Context = UserContext.Current;
                {
                    SecurityRole SecurityRole = null;
                    SecurityRole = Context.Roles.FirstOrDefault(Rl => Rl.RoleName == roleName);
                    if (SecurityRole == null)
                    {
                        SecurityRole newSecurityRole = new SecurityRole
                        {
                            RoleId = Guid.NewGuid(),
                            RoleName = roleName
                        };
                        Context.Roles.Add(newSecurityRole);
                        Context.SaveChanges();
                    }
                }
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return false;
            }
            var Context = UserContext.Current;
            {
                SecurityRole SecurityRole = null;
                SecurityRole = Context.Roles.FirstOrDefault(Rl => Rl.RoleName == roleName);
                if (SecurityRole == null)
                {
                    return false;
                }
                if (throwOnPopulatedRole)
                {
                    if (SecurityRole.Users.Any())
                    {
                        return false;
                    }
                }
                else
                {
                    SecurityRole.Users.Clear();
                }
                Context.Roles.Remove(SecurityRole);
                Context.SaveChanges();
                return true;
            }
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            var Context = UserContext.Current;
            {
                List<SecurityUser> Users = Context.Users.Where(Usr => usernames.Contains(Usr.Username)).ToList();
                List<SecurityRole> Roles = Context.Roles.Where(Rl => roleNames.Contains(Rl.RoleName)).ToList();
                foreach (SecurityUser user in Users)
                {
                    foreach (SecurityRole role in Roles)
                    {
                        user.SecurityRole = role;
                    }
                }
                Context.SaveChanges();
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            var Context = UserContext.Current;
            {
                foreach (String username in usernames)
                {
                    String us = username;
                    SecurityUser securityUser = Context.Users.FirstOrDefault(U => U.Username == us);
                    if (securityUser != null)
                    {
                        foreach (String roleName in roleNames)
                        {
                            String rl = roleName;
                            if (securityUser.SecurityRole.RoleName == rl)
                            {
                                securityUser.SecurityRole = null;
                            }
                        }
                    }
                }
                Context.SaveChanges();
            }
        }
    }
}