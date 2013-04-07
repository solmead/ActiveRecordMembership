using System;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Migrations;
using System.Linq;
using System.Web;
using ActiveRecordMembership.Entities;
using HttpObjectCaching;

namespace ActiveRecordMembership.Context
{
    public class UserContext : ActiveRecord.CodeFirst.Context
    {
        private SecurityUser _currentSecurityUser = null;

        public DbSet<SecurityUser> Users { get; set; }
        public DbSet<SecurityRole> Roles { get; set; }
        public DbSet<SecurityArea> SecurityAreas { get; set; }
        public DbSet<SecuritySetting> SecuritySettings { get; set; }
        public DbSet<UserTracking> UserTrackings { get; set; }
        
   
        
        public static UserContext Current
        {
            get
            {
                var context = Cache.GetItem<UserContext>(CacheArea.Request, "UserContext");
                if (context == null)
                {
                    context = new UserContext();
                    Cache.SetItem(CacheArea.Request, "UserContext", context);
                }
                return context;
            }
        }
        public UserContext() : base("name=DefaultConnection")
        {

        }
        private SecurityUser CachedSecurityUser
        {
            get
            {
                return Cache.GetItem<SecurityUser>(CacheArea.Session, "CachedSecurityUser_UC");
            }
            set
            {
                Cache.SetItem(CacheArea.Session, "CachedSecurityUser_UC", value);
            }
        }

        

        public SecurityUser CurrentSecurityUser
        {
            get
            {
                if (_currentSecurityUser==null)
                {
                    if (CachedSecurityUser == null)
                    {
                        var u = SecurityUser.CurrentUser(this);
                        if (u != null)
                        {
                            u.AddTrackingEvent(DateTime.Now, TrackType.CameBack,
                                               HttpContext.Current.Request.UserHostAddress);
                            u.Save(this);
                        }

                        //this.Entry(u).State = EntityState.Detached;
                        CachedSecurityUser = u;

                    }
                    _currentSecurityUser = CachedSecurityUser;
                }


                //var u = System.Web.Security.Membership.GetUser(false);

                //if ((u != null) && (u.ProviderUserKey!=null) && (_currentSecurityUser == null || _currentSecurityUser.Id != (int) u.ProviderUserKey))
                //{
                //    if ((CachedSecurityUser == null) || (_currentSecurityUser != null))
                //    {
                //        _currentSecurityUser = SecurityUser.CurrentUser(this);
                //        CachedSecurityUser = _currentSecurityUser;
                //    }
                //    else
                //    {
                //        _currentSecurityUser = CachedSecurityUser;
                //    }
                //} else if (u == null || u.ProviderUserKey == null)
                //{
                //    _currentSecurityUser = null;
                //    CachedSecurityUser = null;
                //}
                return _currentSecurityUser;
            }
            set
            {
                _currentSecurityUser = value;
                CachedSecurityUser = _currentSecurityUser;
            }
           
        }

    }
}
