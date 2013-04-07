using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ActiveRecordMembership
{
    public static class Extensions
    {
        public static DateTime GetValue(this DateTime? date)
        {
            if (date.HasValue)
            {
                return date.Value;
            } else
            {
                return new DateTime();
            }
        }
    }
}
