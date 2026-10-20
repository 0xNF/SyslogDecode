// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using SyslogDecode.Model;
using SyslogDecode.Parsing.Extractors;
using SyslogDecode.Parsing.VariantParsers;

namespace SyslogDecode.Parsing
{
    /// <summary>Configurable syslog message parser for multiple message formats (RFCs). </summary>
    /// <remarks>
    ///    Holds a configurable list of parsers for handling specific version/formats, and a 
    ///    list of value extractors for pattern-based extraction.   
    /// </remarks>
    public class SyslogMessageParser
    {
        public readonly List<ISyslogVariantParser> VariantParsers = [];
        public readonly List<IValuesExtractor> ValueExtractors = [];

        /// <summary> Creates and configures a default parser, with support for all major syslog versions 
        ///     and IP addresses extractor. 
        /// </summary>
        /// <returns>Syslog parser instance.</returns>
        /// <remarks>The default parser contains a number of parsers for specific syslog formats: RFC-5424, RFC-3164, 
        /// key-value pairs parser, and plain text parser. It also adds IP addresses extractor that extracts IPv4 and IPv6
        /// addresses from the messages and places them into ExtractedData dictionary field of the output parsed message.
        /// </remarks>
        public static SyslogMessageParser CreateDefault()
        {
            SyslogMessageParser parser = new();
            parser.AddVariantParsers(new Rfc5424SyslogParser(), new KeyValueListParser(),
                                     new Rfc3164SyslogParser(), new PlainTextParser());
            parser.AddValueExtractors(new IpAddressesExtractor());
            return parser;
        }

        /// <summary>Adds a list of format-specific parsers. </summary>
        /// <param name="parsers">A list of parsers.</param>
        public void AddVariantParsers(params ISyslogVariantParser[] parsers)
        {
            VariantParsers.AddRange(parsers);
        }

        /// <summary>Adds a list of pattern-based value extractors. </summary>
        /// <param name="extractors">A list of extractors.</param>
        public void AddValueExtractors(params IValuesExtractor[] extractors)
        {
            ValueExtractors.AddRange(extractors);
        }

        /// <summary>Parses a raw syslog message and returns a parsed message object. </summary>
        /// <param name="rawMessage">Raw syslog message.</param>
        /// <returns></returns>
        public ParsedSyslogMessage Parse(RawSyslogMessage rawMessage)
        {
            ParserContext ctx = new(rawMessage);
            Parse(ctx);
            return ctx.ParsedMessage;
        }

        /// <summary>Attempts to parse raw syslog message and returns the parsed message object as the out parsed parameter </summary>
        /// <param name="rawMessage">Raw syslog message.</param>
        /// <returns></returns>
        public bool TryParse(RawSyslogMessage rawMessage, out ParsedSyslogMessage? parsed)
        {
            parsed = default;
            ParserContext ctx = new(rawMessage);
            try
            {
                Parse(ctx);
                parsed = ctx.ParsedMessage;
                return true;
            }
            catch
            {
                return false;
            }
        }


        internal void Parse(ParserContext context)
        {
            if (!context.ReadSyslogPrefix())
            {
                ReadAsNotSyslog(context);
                return;
            }

            context.AssignFacilitySeverity();

            foreach (ISyslogVariantParser parser in VariantParsers)
            {
                _ = context.Reset();
                try
                {
                    if (parser.TryParse(context))
                    {
                        ExtractDataFromMessage(context);
                        BuildAllDataDictionary(context.ParsedMessage); // put all parsed/extracted data into AllData dictionary
                        return;
                    }
                }
                catch (Exception ex)
                {
                    context.ErrorMessages.Add(ex.ToString() + " message: " + context.Text);
                    ex.Data["SyslogMessage"] = context.Text;
                    throw;
                }
            }
        }

        /// <summary>Keeps text without a valid &lt;n&gt; prefix as the message, with the priority 13 (user.notice) and the time of receipt
        /// that RFC-3164 section 4.3.3 has a relay give it. </summary>
        private static void ReadAsNotSyslog(ParserContext context)
        {
            ParsedSyslogMessage message = context.ParsedMessage;
            message.PayloadType = PayloadType.NotSyslog;
            message.Facility = Facility.UserLevel;
            message.Severity = Severity.Notice;
            message.Header.Timestamp = message.Source?.ReceivedOn;
            message.Message = context.Text;
        }

        private void ExtractDataFromMessage(ParserContext ctx)
        {
            ParsedSyslogMessage entry = ctx.ParsedMessage;
            IList<NameValuePair> data = entry.ExtractedTuples;
            // For RFC-5424 and KeyValue payload types, everything is already structured and extracted
            // But we want to run IP values detector against all of them
            switch (entry.PayloadType)
            {
                case PayloadType.Rfc5424:
                    IEnumerable<NameValuePair> allParams = entry.StructuredData5424.SelectMany(e => e.Value);
                    IList<NameValuePair> Ips = IpAddressesExtractor.ExtractIpAddresses(allParams);
                    data.AddRange(Ips);
                    return;

                case PayloadType.KeyValuePairs:
                    IList<NameValuePair> Ips2 = IpAddressesExtractor.ExtractIpAddresses(entry.ExtractedTuples);
                    data.AddRange(Ips2);
                    return;
            }

            // otherwise run extractors from plain message
            if (entry == null || string.IsNullOrWhiteSpace(entry.Message) || entry.Message.Length < 10)
            {
                return;
            }

            foreach (IValuesExtractor extr in ValueExtractors)
            {
                IList<NameValuePair> values = extr.ExtractValues(ctx);
                if (values != null && values.Count > 0)
                {
                    data.AddRange(values);
                }
            }
        }

        /// <summary>Merges all parsed and extracted data into a single Data dictionary. </summary>
        /// <param name="message"></param>
        private static void BuildAllDataDictionary(ParsedSyslogMessage message)
        {
            // ExtractedData is key-values extracted from syslog body by extractors
            // entry.StructuredData is RFC-5424 structured data; 
            List<NameValuePair> allTuples = [.. message.ExtractedTuples];

            // This is RFC-5424 specific data, structured in its own way - we take all parameters (kv pairs) from there
            IDictionary<string, IList<NameValuePair>> structData = message.StructuredData5424;
            if (structData != null)
            {
                IEnumerable<NameValuePair> structDataParams = structData.SelectMany(de => de.Value);
                allTuples.AddRange(structDataParams);
            }

            // now convert to dictionary; first group values by name
            Dictionary<string, string[]> groupedTuples = allTuples.GroupBy(p => p.Name, p => p.Value).ToDictionary(g => g.Key, g => g.ToArray());
            // copy to final dictionary - keep multiple values as an array; 
            // for single value put it as a single object (not object[1]); - except for IP addresses - these are always arrays, even if there's only one
            message.Data.Clear();
            foreach (KeyValuePair<string, string[]> kv in groupedTuples)
            {
                if (kv.Value.Length > 1 || kv.Key == "IPv4" || kv.Key == "IPv6")
                {
                    message.Data[kv.Key] = kv.Value; //array
                }
                else
                {
                    message.Data[kv.Key] = kv.Value[0]; //single value
                }
            }
        }

    }
}
