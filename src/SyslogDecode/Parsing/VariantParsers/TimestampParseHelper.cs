// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using System;
using System.Globalization;
using System.Linq;

namespace SyslogDecode.Parsing.VariantParsers
{
    public static class TimestampParseHelper
    {
        private static readonly string[] _months = "Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec".ToUpperInvariant().Split(',');
        private static readonly string[] _timezones = "UTC,GMT,PDT,PST,IST,EST,EDT,JST".Split(',');

        public static bool TryParseTimestamp(ParserContext ctx)
        {
            try
            {
                return TryParseTimestampImpl(ctx);
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool TryParseTimestampImpl(ParserContext ctx)
        {
            // sometimes there's starting space
            if (ctx.Current == SyslogChars.Space)
            {
                ctx.SkipSpaces();
            }

            // some messages start with some numeric Id: 
            // <139>36177473: Mar  4 17:21:18 UTC: 
            if (char.IsDigit(ctx.Current))
            {
                // make sure it's not a year and at least 5 chars
                // bug fix - make sure you have at least 5 chars in the string
                bool fiveDigits = ctx.Text.Length > ctx.Position + 5 && ctx.Text.Substring(ctx.Position, 5).All(ch => char.IsDigit(ch));
                if (fiveDigits)
                {
                    int savePos = ctx.Position;
                    _ = ctx.ReadDigits(20);
                    if (ctx.Match(": "))
                    {
                        // we swallowed this numeric prefix and ': ' after that, nothing to do
                    }
                    else
                    {
                        ctx.Position = savePos; // rollback, timestamp evaluation will go from string start
                    }
                }
            }
            bool result = TryParseIfStartsWithYear(ctx) || TryParseIfStartsWithColonThenYear(ctx) ||
                TryParseTimestampWithMonthName(ctx) || TryParseIfStartsWithSpace(ctx);
            return result;

        }

        public static DateTime? ParseStandardTimestamp(this ParserContext ctx)
        {
            string ts = ctx.ReadWord();
            if (ts == null)
            {
                return null;
            }

            if (DateTime.TryParse(ts, out DateTime dt))
            {
                // by default TryParse produces local time
                return dt.ToUniversalTime();
            }
            ctx.AddError($"Invalid timestamp '{ts}'.");
            return DateTime.MinValue;
        }



        // match entry like  
        //  <141>2020-03-04T17:20:54.412705+00:00 MWH....
        private static bool TryParseIfStartsWithYear(ParserContext ctx)
        {
            int year = DateTime.UtcNow.Year;
            int savePos = ctx.Position;
            if (ctx.Match($"{year}-") || ctx.Match($"{year - 1}-")) //(also check prior year)
            {
                ctx.Position = savePos;
                int spPos = ctx.Text.IndexOf(' ', ctx.Position);// 
                if (spPos > 0)
                {
                    string dtStr = ctx.Text[ctx.Position..spPos];
                    ctx.Position = spPos;
                    if (DateTime.TryParse(dtStr, out DateTime dt))
                    {
                        ctx.ParsedMessage.Header.Timestamp = dt.ToUniversalTime();
                        return true;
                    }
                }
            }
            ctx.Position = savePos;
            return false;
        }

        private static bool TryParseTimestampWithMonthName(ParserContext ctx)
        {
            if (ctx.Text.Length < ctx.Position + 21)
            {
                return false;
            }

            string tsStr = ctx.Text.Substring(ctx.Position, 20);
            if (tsStr.StartsWith(": "))
            {
                tsStr = tsStr[2..];
            }

            if (tsStr.Contains('/'))
            {
                return false;
            }

            string[] words = tsStr.Split([' '], StringSplitOptions.RemoveEmptyEntries);
            if (words.Length < 4)
            {
                return false;
            }

            string? year = null;
            string? month = null;
            string? day = null;
            string? time = null;
            string? tz = null;
            int y = DateTime.UtcNow.Year;
            string thisYear = y.ToString();
            string prevYear = (y - 1).ToString();
            string lastWord = string.Empty;
            // Take first 5 words and try to understand what it is
            for (int i = 0; i < 5; i++)
            {
                if (i >= words.Length)
                {
                    break;
                }

                string word = words[i];
                if (word == thisYear || word == prevYear)
                {
                    year = word;
                }
                else if (word.Length == 3 && _months.Contains(word.ToUpperInvariant()))
                {
                    month = word;
                }
                else if (word.Length < 3 && int.TryParse(word, out _))
                {
                    day = word;
                }
                else if (word.Contains(':') && word.Split(':').Length == 3 && TimeSpan.TryParse(word, CultureInfo.InvariantCulture, out _))
                {
                    time = word;
                    lastWord = word;
                }
                else if (word.Length == 4 && word.EndsWith(':'))
                {
                    string w3 = word[..3].ToUpperInvariant();
                    if (_timezones.Contains(w3))
                    {
                        tz = w3;
                        lastWord = word;
                        break; //for loop
                    }
                }
            }
            // check if we have enough - at least month, day and time
            if (month == null || day == null || time == null)
            {
                return false;
            }

            year ??= GuessYear(month).ToString();

            ctx.ParsedMessage.Header.Timestamp = ConstructDateTime(year, month, day, time, tz);
            // advance position
            ctx.Position = ctx.Text.IndexOf(lastWord, ctx.Position) + lastWord.Length;
            return true;
        }

        private static DateTime ConstructDateTime(string year, string month, string day, string time, string? tz)
        {
            int y = int.Parse(year, CultureInfo.InvariantCulture);
            int m = MonthNumber(month);
            int d = int.Parse(day, CultureInfo.InvariantCulture);
            _ = TimeSpan.TryParse(time, CultureInfo.InvariantCulture, out TimeSpan t);
            return ToUtc(new DateTime(y, m, d).Add(t), tz);
        }

        private static int MonthNumber(string month)
        {
            return Array.IndexOf(_months, month.ToUpperInvariant()) + 1;
        }

        /// <summary>Converts a clock time to UTC: from the zone named, or, with no zone, from the receiver's local zone,
        /// as an RFC-3164 time is the sender's clock and a sender on the same host shares it. </summary>
        private static DateTime ToUtc(DateTime clock, string? zone)
        {
            return zone != null && TryGetZoneOffset(zone, out TimeSpan offset)
                ? DateTime.SpecifyKind(clock - offset, DateTimeKind.Utc)
                : DateTime.SpecifyKind(clock, DateTimeKind.Local).ToUniversalTime();
        }

        private static bool TryGetZoneOffset(string zone, out TimeSpan offset)
        {
            TimeSpan? known = zone switch
            {
                "UTC" or "GMT" => TimeSpan.Zero,
                "PDT" => TimeSpan.FromHours(-7),
                "PST" => TimeSpan.FromHours(-8),
                "EDT" => TimeSpan.FromHours(-4),
                "EST" => TimeSpan.FromHours(-5),
                "IST" => new TimeSpan(5, 30, 0),
                "JST" => TimeSpan.FromHours(9),
                _ => null,
            };
            offset = known ?? TimeSpan.Zero;
            return known.HasValue;
        }


        // guess year for a month: the current year, unless the month is more than one month ahead of now,
        // which makes it last year's, as a December entry read in January is
        private static int GuessYear(string month)
        {
            DateTime now = DateTime.UtcNow;
            return MonthNumber(month) > now.Month + 1 ? now.Year - 1 : now.Year;
        }

        // match entry like  
        //  <186>: 2020 Mar  4 17:20:54.183 UTC:
        private static bool TryParseIfStartsWithColonThenYear(ParserContext ctx)
        {
            int year = DateTime.UtcNow.Year;
            int savePos = ctx.Position;
            if (ctx.Match(": ") && (ctx.Match($"{year}") || ctx.Match($"{year - 1}"))) //check prior year
            {
                // we already matched beyond year; move back:
                ctx.Position = savePos + ": ".Length;
                // the time ends at the first known zone followed by a colon, as in " UTC:"
                (int zonePos, string? zone) = _timezones
                    .Select(z => (Pos: ctx.Text.IndexOf($" {z}:", ctx.Position, StringComparison.Ordinal), Zone: z))
                    .Where(found => found.Pos > 0)
                    .OrderBy(found => found.Pos)
                    .Select(found => (found.Pos, (string?)found.Zone))
                    .FirstOrDefault();
                if (zone != null)
                {
                    string dtStr = ctx.Text[ctx.Position..zonePos];
                    ctx.Position = zonePos + zone.Length + 2;
                    if (DateTime.TryParse(dtStr, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out DateTime dt))
                    {
                        ctx.ParsedMessage.Header.Timestamp = ToUtc(dt, zone);
                        return true;
                    }
                }
            }
            ctx.Position = savePos;
            return false;
        }

        // match entry like  
        //  <134> 03/04/2020:17:20:58 GMT ams07....
        private static bool TryParseIfStartsWithSpace(ParserContext ctx)
        {
            _ = ctx.Reset();
            if (ctx.Current != SyslogChars.Space)
            {
                return false;
            }

            string prefix = ctx.Text.Substring(ctx.Position, 25);
            int year = DateTime.UtcNow.Year;
            if (prefix.Contains($"/{year}:") || prefix.Contains($"/{year - 1}:")) //(also check prior year)
            {
                ctx.Position++;
                int spPos = ctx.Text.IndexOf(' ', ctx.Position);
                if (spPos > 0)
                {
                    string dtStr = ctx.Text[ctx.Position..spPos];
                    ctx.Position = spPos + 1;
                    _ = ctx.Match("GMT"); //skip also GMT
                    if (DateTime.TryParse(dtStr, out DateTime dt) ||
                        DateTime.TryParseExact(dtStr, "MM/dd/yyyy:HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out dt))
                    {
                        ctx.ParsedMessage.Header.Timestamp = dt.ToUniversalTime();
                    }
                }
                return true;
            }
            return false;
        }

    }
}
