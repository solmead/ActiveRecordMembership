using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using ActiveRecord.CodeFirst;

namespace ActiveRecordMembership.Entities
{
    public enum TrackType
    {
        [Description("Logged In")]
        LoggedIn,
        [Description("Logged Out")]
        LoggedOut,
        [Description("Session Ended")]
        SessionEnded,
        [Description("Came Back")]
        CameBack
    }

    [Table("UserTracking")]
    public class UserTracking : Record<UserTracking>
    {
        public int Id { get; set; }
        [Display(Name="User")]
        [Required]
        public int User_ID { get; set; }

        [Display(Name = "Time Stamp")]
        public DateTime? TimeStamp { get; set; }
        [Display(Name = "IP Address")]
        public string IPAddress { get; set; }
        [ScaffoldColumn(false)]
        [Column("WhatHappened")]
        public string WhatHappenedString { get; set; }
        [NotMapped]
        [Display(Name = "What Happened")]
        public TrackType WhatHappened
        { 
            get
            {
                TrackType r;
                Enum.TryParse(WhatHappenedString, true,out r);
                return r;
            }
            set { WhatHappenedString = value.ToString(); }
        }

        [Display(Name = "User")]
        [ForeignKey("User_ID")]
        public virtual SecurityUser User { get; set; }
    }
}
