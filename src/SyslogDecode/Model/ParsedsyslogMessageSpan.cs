// // /********************************************************
// // *                                                       *
// // *   Copyright (C) Microsoft. All rights reserved.       *
// // *                                                       *
// // ********************************************************/

// using System;
// using System.Collections.Generic;
// using System.Diagnostics;
// using System.Text.Json.Serialization;

// namespace SyslogDecode.Model
// {

//     /// <summary>Defines the structure of a Syslog entry. </summary>
//     [DebuggerDisplay("{Header}")]
//     public ref struct ParsedSyslogMessageSpan
//     {
//         [JsonPropertyName("PayloadType")]
//         public PayloadType PayloadType { get; set; }
//         [JsonPropertyName("Facility")]
//         public Facility Facility { get; set; }
//         [JsonPropertyName("Severity")]
//         public Severity Severity { get; set; }
//         [JsonPropertyName("Header")]
//         public SyslogHeaderSpan Header { get; set; }

//         [JsonIgnore]
//         public bool HasHeader { get; set; }

//         [JsonPropertyName("Message")]
//         public ReadOnlySpan<char> Message { get; set; }

//         [JsonIgnore]
//         public bool HasMessage { get; set; }

//         /// <summary>The StructuredData element for entries following RFC-5424 spec. It is a list of named elements, 
//         /// each having a list of name-value pairs. </summary>
//         /// <remarks>Keys inside element can be repeated (see RFC 5424, example with IP parameter), so element value is a list of pairs, not dictionary.</remarks>
//         [JsonPropertyName("StructuredData")]
//         public IDictionary<string, IList<NameValuePairSpan>> StructuredData5424 { get; set; } = new Dictionary<string, IList<NameValuePairSpan>>();

//         /// <summary>Data extracted from text message sections using various extraction methods, mostly pattern-matching. Keys/names can be repeated, 
//         /// so the data is represented as list of key-value pairs, not dictionary. </summary>
//         [JsonIgnore]
//         public IList<NameValuePairSpan> ExtractedTuples = [];

//         /// <summary>All data, parsed and extracted, represented as a Dictionary. Values from the <see cref="StructuredData5424"/> and <see cref="ExtractedTuples"/>
//         /// are combined in this single dictionary. </summary>
//         /// <remarks>Each value in a dictionary is either a single value, or an array of strings, if there is more than one value.
//         /// The exception is IPv4 and IPv6 entries, which are always arrays, even if there is just one value. This is done for conveniences 
//         /// of querying the data in databases like Kusto. </remarks>
//         [JsonIgnore]
//         public IDictionary<string, object> Data = new Dictionary<string, object>();

//         /// <summary>Source raw syslog message. </summary>
//         [JsonIgnore]
//         public RawSyslogMessage? Source;

//         /// <summary>Parsing error messages.</summary>
//         [JsonIgnore]
//         public readonly List<string> ErrorMessages = [];

//         public ParsedSyslogMessageSpan(RawSyslogMessage source)
//         {
//             Source = source;
//             Header = new SyslogHeaderSpan();
//         }

//         public ParsedSyslogMessageSpan(Facility facility, Severity severity, DateTime? timestamp = null, string? hostName = null,
//                            string? appName = null, string? procId = null, string? msgId = null, string? message = null)
//         {
//             PayloadType = PayloadType.Rfc5424;
//             Facility = facility;
//             Severity = severity;
//             timestamp ??= DateTime.UtcNow;
//             Header = new SyslogHeaderSpan()
//             {
//                 Timestamp = timestamp,
//                 HostName = hostName,
//                 AppName = appName,
//                 ProcId = procId,
//                 MsgId = msgId //Version should always be 1
//             };
//             Message = message;
//         }

//         public override readonly string? ToString()
//         {
//             return HasHeader ? Header.ToString() : null;
//         }
//     }

//     public ref struct SyslogHeaderSpan
//     {
//         [JsonPropertyName("Timestamp")]
//         public DateTime? Timestamp { get; set; }

//         [JsonPropertyName("HostName")]
//         public ReadOnlySpan<char> HostName { get; set; }

//         [JsonIgnore]
//         public bool HasHostName { get; set; }

//         [JsonPropertyName("AppName")]
//         public ReadOnlySpan<char> AppName { get; set; }

//         [JsonIgnore]
//         public bool HasAppName { get; set; }


//         [JsonPropertyName("ProcId")]
//         public ReadOnlySpan<char> ProcId { get; set; }

//         [JsonIgnore]
//         public bool HasProcId { get; set; }


//         [JsonPropertyName("MsgId")]
//         public ReadOnlySpan<char> MsgId { get; set; }

//         [JsonIgnore]
//         public bool HasMsgId { get; set; }


//         [JsonPropertyName("Version")]
//         public int Version { get; set; }

//         public override readonly string ToString()
//         {
//             return $"{Timestamp} version:{Version} host:{(HasHostName ? HostName : null)} app: {(HasAppName ? AppName : null)}";
//         }
//     }


//     [DebuggerDisplay("{Name}={Value}")]
//     public ref struct NameValuePairSpan
//     {
//         [JsonPropertyName("Name")]
//         public required ReadOnlySpan<char> Name { get; set; }
//         [JsonPropertyName("Value")]
//         public required ReadOnlySpan<char> Value { get; set; }
//     }


// }
