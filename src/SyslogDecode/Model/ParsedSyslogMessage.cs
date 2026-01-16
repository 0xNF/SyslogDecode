// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SyslogDecode.Model
{
    /// <summary>Defines the structure of a Syslog entry. </summary>
    [DebuggerDisplay("{Header}")]
    public class ParsedSyslogMessage
    {
        [JsonPropertyName("PayloadType")]
        public PayloadType PayloadType { get; set; }
        [JsonPropertyName("Facility")]
        public Facility Facility { get; set; }
        [JsonPropertyName("Severity")]
        public Severity Severity { get; set; }
        [JsonPropertyName("Header")]
        public SyslogHeader Header { get; set; }
        [JsonPropertyName("Message")]
        public string? Message { get; set; }

        /// <summary>The StructuredData element for entries following RFC-5424 spec. It is a list of named elements, 
        /// each having a list of name-value pairs. </summary>
        /// <remarks>Keys inside element can be repeated (see RFC 5424, example with IP parameter), so element value is a list of pairs, not dictionary.</remarks>
        [JsonPropertyName("StructuredData")]
        public IDictionary<string, IList<NameValuePair>> StructuredData5424 { get; set; } = new Dictionary<string, IList<NameValuePair>>();

        /// <summary>Data extracted from text message sections using various extraction methods, mostly pattern-matching. Keys/names can be repeated, 
        /// so the data is represented as list of key-value pairs, not dictionary. </summary>
        [JsonIgnore]
        public IList<NameValuePair> ExtractedTuples = [];

        /// <summary>All data, parsed and extracted, represented as a Dictionary. Values from the <see cref="StructuredData5424"/> and <see cref="ExtractedTuples"/>
        /// are combined in this single dictionary. </summary>
        /// <remarks>Each value in a dictionary is either a single value, or an array of strings, if there is more than one value.
        /// The exception is IPv4 and IPv6 entries, which are always arrays, even if there is just one value. This is done for conveniences 
        /// of querying the data in databases like Kusto. </remarks>
        [JsonIgnore]
        public IDictionary<string, object> Data = new Dictionary<string, object>();

        /// <summary>Source raw syslog message. </summary>
        [JsonIgnore]
        public RawSyslogMessage? Source;

        /// <summary>Parsing error messages.</summary>
        [JsonIgnore]
        public readonly List<string> ErrorMessages = [];

        public ParsedSyslogMessage(RawSyslogMessage source)
        {
            Source = source;
            Header = new SyslogHeader();
        }

        public ParsedSyslogMessage(Facility facility, Severity severity, DateTime? timestamp = null, string? hostName = null,
                           string? appName = null, string? procId = null, string? msgId = null, string? message = null)
        {
            PayloadType = PayloadType.Rfc5424;
            Facility = facility;
            Severity = severity;
            timestamp ??= DateTime.UtcNow;
            Header = new SyslogHeader()
            {
                Timestamp = timestamp,
                HostName = hostName,
                AppName = appName,
                ProcId = procId,
                MsgId = msgId //Version should always be 1
            };
            Message = message;
        }

        public override string? ToString()
        {
            return Header?.ToString();
        }
    }

    public class SyslogHeader
    {
        [JsonPropertyName("Timestamp")]
        public DateTime? Timestamp { get; set; }
        [JsonPropertyName("HostName")]
        public string? HostName { get; set; }
        [JsonPropertyName("AppName")]
        public string? AppName { get; set; }
        [JsonPropertyName("ProcId")]
        public string? ProcId { get; set; }
        [JsonPropertyName("MsgId")]
        public string? MsgId { get; set; }
        [JsonPropertyName("Version")]
        public int Version { get; set; }
        public override string ToString()
        {
            return $"{Timestamp} version:{Version} host:{HostName} app: {AppName}";
        }
    }


    [DebuggerDisplay("{Name}={Value}")]
    public class NameValuePair
    {
        [JsonPropertyName("Name")]
        public required string Name { get; set; }
        [JsonPropertyName("Value")]
        public required string Value { get; set; }
    }



    [JsonSerializable(typeof(SyslogHeader))]
    [JsonSerializable(typeof(ParsedSyslogMessage))]
    [JsonSerializable(typeof(List<ParsedSyslogMessage>))]
    [JsonSerializable(typeof(ParsedSyslogMessage[]))]
    [JsonSerializable(typeof(Severity))]
    [JsonSerializable(typeof(Facility))]
    [JsonSerializable(typeof(PayloadType))]
    public partial class SyslogDecodeJsonSerializerContext : JsonSerializerContext
    {

    }

}
