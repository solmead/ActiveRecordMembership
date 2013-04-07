using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Linq;
using System.Web.Mvc;
using ActiveRecord.CodeFirst;
using ActiveRecordMembership.Context;
using ActiveRecordMembership.Entities.Membership;
using DataAnnotationsExtensions;

namespace ActiveRecordMembership.Entities
{
    //[Bind(Exclude = "UserId, Password, IsApproved, PasswordFailuresSinceLastSuccess, LastActivityDate, LastLockoutDate, LastLoginDate, ConfirmationToken, CreateDate, IsLockedOut, LastPasswordChangedDate, PasswordVerificationToken, PersonId, PasswordVerificationTokenExpirationDate")]
    [Table("SecurityUsers")]
    [Bind(Exclude = "Id, EncryptedPassword, Salt, PasswordFailuresSinceLastSuccess, LastPasswordFailureDate, LastActivityDate, LastLockoutDate, CreateDate, IsLockedOut, LastPasswordChangedDate")]
    public class SecurityUser : Record<SecurityUser>
    {
        public SecurityUser()
        {
            UserTrackings = new List<UserTracking>();
            
        }
        [ScaffoldColumn(false)]
        [Key]
        public int Id { get; set; }


        [Required]
        [Display(Name="User Name", Description="Login name of user")]
        public String Username { get; set; }

        [Display(Name = "First Name")]
        public virtual String FirstName { get; set; }
        [Display(Name = "Last Name")]
        public virtual String LastName { get; set; }

        [Required]
        [Display(Name = "E-Mail")]
        [Email]
        public String Email { get; set; }

        [Display(Name = "Phone Number")]
        public String PhoneNumber { get; set; }

        [ScaffoldColumn(false)]
        [DataType(DataType.Password)]
        public String EncryptedPassword { get; set; }

        [ScaffoldColumn(false)]
        [Column("Salt")]
        [MaxLength(500)]
        public string OldSalt { get; set; }

        public virtual Boolean Enabled { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Password Failures Since Last success")]
        public virtual int PasswordFailuresSinceLastSuccess { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Last Password Failure Date")]
        public virtual DateTime? LastPasswordFailureDate { get; set; }
        [ScaffoldColumn(false)]
        [Column("LastPageAccess")]
        [Display(Name = "Last Activity Date")]
        public virtual DateTime? LastActivityDate { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Last Lockout Date")]
        public virtual DateTime? LastLockoutDate { get; set; }

        [Column("LastLogin")]
        [Display(Name = "Last Login Date/Time:")]
        public virtual DateTime? LastLoginDate { get; set; }
        //[ScaffoldColumn(false)]
        //public virtual String ConfirmationToken { get; set; }
        [ScaffoldColumn(false)]
        public virtual DateTime? CreateDate { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Is Locked Out")]
        public virtual Boolean IsLockedOut { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Force Change Password")]
        public virtual Boolean ForceChangePassword { get; set; }
        [ScaffoldColumn(false)]
        [Display(Name = "Last Time Password Was Changed")]
        public virtual DateTime? LastPasswordChangedDate { get; set; }
        //[ScaffoldColumn(false)]
        //public virtual String PasswordVerificationToken { get; set; }
        //[ScaffoldColumn(false)]
        //public virtual DateTime? PasswordVerificationTokenExpirationDate { get; set; }

        [Display(Name = "Access Level")]
        [ForeignKey("SecurityRole")]
        public virtual Guid? RoleId { get; set; }
        //[InverseProperty("Users")]
        public virtual SecurityRole SecurityRole { get; set; }
        [InverseProperty("User")]
        public virtual ICollection<UserTracking> UserTrackings { get; set; }

        [NotMapped]
        public string FullName
        {
            get { return FirstName + " " + LastName; }
        }

        public void AddTrackingEvent(DateTime when, TrackType what, string ipAddress)
        {
            var te = new UserTracking()
                {
                    User = this,
                    TimeStamp = when,
                    WhatHappened = what,
                    IPAddress = ipAddress 
                };
            UserTrackings.Add(te);
        }

        public bool SecuritySettingAtLeast(System.Data.Entity.DbContext db,string areaName, SecurityLevelEnum minimumLevel)
        {
            return (SecurityRole.GetSettingByArea(db,areaName).Level >= minimumLevel);
        }
        public static IQueryable< SecurityUser>  GetListOrdered(System.Data.Entity.DbContext db)
        {
            return (from u in db.Set<SecurityUser>() orderby u.Username, u.LastName,u.FirstName select u);
        }
            
            
        public SecuritySetting GetSecuritySetting(System.Data.Entity.DbContext db,string areaName)
        {
            return SecurityRole.GetSettingByArea(db,areaName);
        }

        public static SecurityUser LoadByName(System.Data.Entity.DbContext db, string name)
        {
            return (from u in db.Set<SecurityUser>() where u.Username == name select u).FirstOrDefault();
        }
        public static SecurityUser LoadByEmail(System.Data.Entity.DbContext db, string email)
        {
            return (from u in db.Set<SecurityUser>() where u.Email == email select u).FirstOrDefault();
        }
        public static SecurityUser CurrentUser(System.Data.Entity.DbContext db)
        {
            SecurityUser user = null;
            try
            {
                var u = System.Web.Security.Membership.GetUser(false);
                if (u != null)
                {
                    var users = (from SecurityUser us in db.Set<SecurityUser>()
                                 where us.Id == (int)u.ProviderUserKey
                                 select us)
                        .Include(us => us.SecurityRole)
                        .Include(us => us.SecurityRole.SecuritySettings)
                        .Include(us => us.SecurityRole.SecuritySettings.Select(od => od.Area));

                    user = users.FirstOrDefault();
                }
            }
            catch (Exception)
            {
                
            }
            return user;
        }
        public static SecurityUser CreateUser(string username, string password, string emailAddress, SecurityRole securityRole, bool enabled = false)
        {

            string HashedPassword = Crypto.HashPassword(password);
            var NewUser = new SecurityUser
            {
                Username = username,
                EncryptedPassword = HashedPassword,
                Enabled = enabled,
                Email = emailAddress,
                CreateDate = DateTime.Now,
                LastPasswordChangedDate = DateTime.Now,
                PasswordFailuresSinceLastSuccess = 0,
                LastLoginDate = DateTime.Now,
                LastActivityDate = DateTime.Now,
                LastLockoutDate = DateTime.Now,
                IsLockedOut = false,
                LastPasswordFailureDate = DateTime.Now
            };
            NewUser.SecurityRole = securityRole;
            return NewUser;
        }
        public bool ChangePassword(System.Data.Entity.DbContext db, string newPassword)
        {
            bool changePasswordSucceeded;
            try
            {
                string HashedPassword = Crypto.HashPassword(newPassword);
                EncryptedPassword = HashedPassword;
                OldSalt = "";
                LastPasswordChangedDate = DateTime.Now;
                changePasswordSucceeded = true;
            }
            catch (Exception)
            {
                changePasswordSucceeded = false;
            }
            return changePasswordSucceeded;
        }
        public override IEnumerable<ValidationResult> ValidateObject(ValidationContext validationContext)
        {
            var list = new List<ValidationResult>();
            list.AddRange(base.ValidateObject(validationContext));
            var db = UserContext.Current;
                var u = SecurityUser.LoadByName(db, Username);
                if (u !=null && u.Id != Id)
                {
                    list.Add(new ValidationResult("User name: [" + Username +"] already exists. [" + u.Id + "] != [" + Id + "]",new List<string>() {"Username"}));
                }
                //u = User.LoadByEmail(db, Email);
                //if (u !=null && u.Id != Id)
                //{
                //    list.Add(new ValidationResult("Email Address: [" + Email + "] already used by a user.", new List<string>() { "Email" }));
                //}
            return list;
        }
    }
}