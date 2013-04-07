using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using ActiveRecord.CodeFirst;
using ActiveRecordMembership.Context;

namespace ActiveRecordMembership.Entities
{
    [Table("SecurityAreas")]
    public class SecurityArea : Record<SecurityArea>
    {
        public int Id { get; set; }
        public string Name { get; set; }


        public static SecurityArea LoadByName(System.Data.Entity.DbContext db, string name)
        {
            return (from sa in db.Set<SecurityArea>() where sa.Name == name select sa).FirstOrDefault();
        }
    }
}
