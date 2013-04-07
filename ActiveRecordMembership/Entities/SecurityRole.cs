using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using ActiveRecord.CodeFirst;
using ActiveRecordMembership.Context;

namespace ActiveRecordMembership.Entities
{
    [Table("Roles")]
    public class SecurityRole : Record<SecurityRole>
    {
        public SecurityRole()
        {
            //Users = new List<User>();
            //UsersRoles = new List<UsersRoles>();
            SecuritySettings = new List<SecuritySetting>();
            //PagesRoles = new List<PagesRoles>();
        }
        [ScaffoldColumn(false)]
        [Key]
        public Guid RoleId { get; set; }

        [ScaffoldColumn(false)]
        public int PresidenceOrder { get; set; }

        [Required]
        [Display(Name="Name")]
        public string RoleName { get; set; }

        public string Description { get; set; }

        [ScaffoldColumn(false)]
        [InverseProperty("SecurityRole")]
        public virtual ICollection<SecurityUser> Users { get; set; }

        public virtual ICollection<SecuritySetting> SecuritySettings { get; set; }

        

        public SecuritySetting GetSettingByArea(System.Data.Entity.DbContext db, string name)
        {
            var item = (from ss in SecuritySettings where ss.Area.Name == name select ss).FirstOrDefault();
            if (item == null)
            {
                var area =
                    (from sa in db.Set<SecurityArea>() where sa.Name == name select sa).FirstOrDefault();
                if (area == null)
                {
                    area = new SecurityArea
                        {
                            Name = name
                        };
                }
                item = new SecuritySetting()
                           {
                               Level = SecurityLevelEnum.No_Access,
                               Area = area
                           };
                SecuritySettings.Add(item);
            }
            return item;
        }
        public SecuritySetting GetSettingByArea(SecurityArea securityArea)
        {
            var item = (from ss in SecuritySettings where ss.Area == securityArea select ss).FirstOrDefault();
            if (item == null)
            {
                item = new SecuritySetting()
                {
                    Level = SecurityLevelEnum.No_Access,
                    Area = securityArea
                };
                SecuritySettings.Add(item);
            }
            return item;
        }
        internal void CheckAreas(System.Data.Entity.DbContext db)
        {
            
            foreach (var sa in db.Set<SecurityArea>().ToList())
            {
                if (!(from ss in SecuritySettings where ss.Area == sa select ss).Any())
                {
                    SecuritySettings.Add(new SecuritySetting()
                    {
                        Area = sa,
                        Level = SecurityLevelEnum.No_Access
                    });
                }
            }
        }

        protected override void HandleDeleteBefore(System.Data.Entity.DbContext db)
        {
            base.HandleDeleteBefore(db);
            //HTML.DeletePartial(db);
            foreach (var c in SecuritySettings)
            {
                c.DeletePartial(db);
            }
            SecuritySettings.Clear();
            foreach (var c in Users)
            {
                c.SecurityRole = null;
            }
        }
        protected override void HandleSaveBefore(System.Data.Entity.DbContext db)
        {
            base.HandleSaveBefore(db);
            //var mDb = db as UserContext;

            CheckAreas(db);
            if (RoleId == Guid.Empty)
            {
                RoleId = Guid.NewGuid();
            }
        }
        public static SecurityRole LoadByName(System.Data.Entity.DbContext db, string name)
        {
            return (from r in db.Set<SecurityRole>() where r.RoleName == name select r).FirstOrDefault();
        }

        public static IQueryable<SecurityRole> GetListOrdered(System.Data.Entity.DbContext db)
        {
            return (from r in db.Set<SecurityRole>() orderby r.PresidenceOrder, r.RoleName  select r);
        }
    }
}