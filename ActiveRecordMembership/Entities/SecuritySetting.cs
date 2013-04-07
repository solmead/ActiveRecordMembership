using System.ComponentModel.DataAnnotations.Schema;
using ActiveRecord.CodeFirst;

namespace ActiveRecordMembership.Entities
{
    public enum SecurityLevelEnum
    {
        No_Access,
        View,
        Edit,
        Create,
        Delete
    }

    [Table("SecuritySettings")]
    public class SecuritySetting : Record<SecuritySetting>
    {
        public int Id { get; set; }

        public virtual SecurityArea Area { get; set; }

        [Column("LevelInt")]
        public SecurityLevelEnum Level { get; set; }

    }
}
