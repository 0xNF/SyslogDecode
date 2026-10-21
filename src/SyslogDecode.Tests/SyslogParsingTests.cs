// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/


namespace SyslogDecode.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using SyslogDecode.Parsing;
    using SyslogDecode.Parsing.Extractors;
    using SyslogDecode.Parsing.VariantParsers;
    using System.Text;
    using SyslogDecode.Model;

    [TestClass]
    public class SyslogParsingTests
    {
        [TestMethod]
        public void TestParserAndSerializer()
        {
            // A sample from RFC 5424, its time written to the microsecond as the serializer writes it
            var header = "<34>1 2003-10-11T22:14:15.003000Z mymachine.example.com su - ID47";
            var structData = "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]";
            var customMsg = "My custom message";

            var parser = SyslogMessageParser.CreateDefault();

            // Test 1 - simple message
            var text1 = header + " " + structData + " " + customMsg;
            var rawMsg = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message =text1 };
            var parsedMsg = parser.Parse(rawMsg);
            Assert.IsNotNull(parsedMsg);
            Assert.AreEqual(0, parsedMsg.ErrorMessages.Count);
            Assert.AreEqual(1, parsedMsg.StructuredData5424.Count, "expected 1 element in structured data");
            var elem1Name = parsedMsg.StructuredData5424.First().Key;
            var elem1Params = parsedMsg.StructuredData5424.First().Value; 
            Assert.AreEqual(3, elem1Params.Count, "Expected 3 parameter");
            var prmEventId = elem1Params.First(p => p.Name == "eventID");
            Assert.AreEqual("1011", prmEventId.Value, "Invalid param value.");

            // Test 2 - escaped chars in param values;  the test value is   \abc\def"ghi 
            // We escape it appropriately is entry text, and parser should 'unescape' it. We use interpolated string to produce string with escapes
            var dq = '"';
            var esc = '\\';
            var structDataWithEscapedChars = $"[exEscapes@123 escParam=\"{esc}{esc}abc{esc}{esc}def{esc}{dq}ghi\"]";

            var text2 = header + " " + structDataWithEscapedChars + " " + customMsg;
            rawMsg = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message =text2 };
            parsedMsg = parser.Parse(rawMsg);
            Assert.IsNotNull(parsedMsg);
            Assert.AreEqual(0, parsedMsg.ErrorMessages.Count);
            var escParam = parsedMsg.StructuredData5424.First().Value[0];
            Assert.AreEqual(@"\abc\def""ghi", escParam.Value, "Invalid value of parameter with escapes.");

            // Test 3: test serializer: serialize entry and compare to original message text
            // Note  that with real messages there maybe mismatches because of slightly different dates formatting by serializer (ex: number of ms in datetime)
            var back2 = SyslogSerializer.Serialize(parsedMsg);
            Assert.AreEqual(text2, back2, "Serialized entry does not match.");

            // Test 4 - using Message field with BOM prefix
            // The parser should strip the BOM
            var msgWithBOM = PrependBOM(customMsg);
            var text3 = header + " " + structDataWithEscapedChars + " " + msgWithBOM;
            rawMsg = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message =text3 };
            parsedMsg = parser.Parse(rawMsg);
            Assert.IsNotNull(parsedMsg);
            Assert.AreEqual(customMsg, parsedMsg.Message, "Message does not match.");

        }

        // Prepends Byte-order-mark sequence, allowed by RFC-5424, to test how it is handled by the parser
        private string PrependBOM(string value)
        {
            var utf8 = Encoding.UTF8; 
            var bytes = utf8.GetBytes(value);
            var bom = utf8.GetPreamble(); //this is BOM
            var allBytes = bom.Concat(bytes).ToArray();
            var result = utf8.GetString(allBytes);
            return result; 
        }

        [TestMethod]
        public void TestBugFixes()
        {
            var parser = SyslogMessageParser.CreateDefault();
            string msg;
            RawSyslogMessage rawMsg;
            ParsedSyslogMessage parsedMsg; 
            bool success; 


            // Parser failure 1
            msg = "<28>Jun 30 14:29:50 Sg2-0102-0201-14T1 snmp#snmp-subagent"; // RFC-3164: no Message element
            rawMsg = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message =msg };
            parsedMsg = parser.Parse(rawMsg);
            Assert.IsTrue(parsedMsg.ErrorMessages.Count == 0, "Failed to parse RFC-3164 message without 'Message' element");

            // Parser failure 2
            msg = "<28>Jun 30 14:29:50 Sg2-0102-0201-14T1 "; //  RFC-3164: no procId
            rawMsg = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message =msg };
            parsedMsg = parser.Parse(rawMsg);
            Assert.IsTrue(parsedMsg.ErrorMessages.Count == 0, "Failed to parse RFC-3164 message without ProcId element");

        }

        [TestMethod]
        public void TestPlainTextIsDatedWhenItWasReceived()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var receivedOn = new DateTime(2026, 10, 21, 1, 2, 3, DateTimeKind.Utc);

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = "<13>Lok'tar ogar, not in any syslog format" });

            Assert.AreEqual(PayloadType.PlainText, parsedMsg.PayloadType);
            Assert.AreEqual(receivedOn, parsedMsg.Header.Timestamp);
        }

        [TestMethod]
        public void TestMessageWithoutValidPriority()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var receivedOn = new DateTime(2026, 10, 21, 1, 2, 3, DateTimeKind.Utc);

            // RFC-3164 section 4.3.3: text without a valid PRI is kept whole, as user.notice at the time of receipt
            foreach (var text in new[] { "hello world, not syslog", "<>1 2003-10-11T22:14:15.003Z host app - - - msg", "<192>1 - - - - - - msg", "<1a>msg" })
            {
                var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = text });
                Assert.AreEqual(PayloadType.NotSyslog, parsedMsg.PayloadType, text);
                Assert.AreEqual(Facility.UserLevel, parsedMsg.Facility, text);
                Assert.AreEqual(Severity.Notice, parsedMsg.Severity, text);
                Assert.AreEqual(receivedOn, parsedMsg.Header.Timestamp, text);
                Assert.AreEqual(text, parsedMsg.Message, text);
            }

            var highest = parser.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = "<191>1 - - app - - - msg" });
            Assert.AreEqual(PayloadType.Rfc5424, highest.PayloadType);
            Assert.AreEqual(Facility.Local7, highest.Facility);
            Assert.AreEqual(Severity.Debug, highest.Severity);
        }

        [TestMethod]
        public void TestSerializerKeepsMicrosecondsAndOneSpaceBeforeMessage()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<174>1 2026-10-20T03:00:00.123456Z Durotar Orgrimmar 21372 - - Lok'tar ogar";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual(text, SyslogSerializer.Serialize(parsedMsg));
        }

        [TestMethod]
        public void TestMessageKeepsItsLeadingSpaces()
        {
            var parser = SyslogMessageParser.CreateDefault();

            foreach (var (text, expected) in new[]
            {
                ("<174>1 - Durotar Orgrimmar - - -   indented", "  indented"),
                ("<174>1 - Durotar Orgrimmar - - [a@1 b=\"c\"]  indented", " indented"),
                ("<174>1 - Durotar Orgrimmar - - - \xFEFF  indented", "  indented"),
                ("<174>1 - Durotar Orgrimmar - - - plain", "plain"),
            })
            {
                var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });
                Assert.AreEqual(expected, parsedMsg.Message, text);
            }
        }

        [TestMethod]
        public void TestHeaderFieldsKeepEqualsAndBrackets()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<174>1 - host[1] app=x proc]2 id=[3] [a@1 b=\"c\"] the message";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual("host[1]", parsedMsg.Header.HostName);
            Assert.AreEqual("app=x", parsedMsg.Header.AppName);
            Assert.AreEqual("proc]2", parsedMsg.Header.ProcId);
            Assert.AreEqual("id=[3]", parsedMsg.Header.MsgId);
            Assert.AreEqual("c", parsedMsg.StructuredData5424["a@1"][0].Value);
            Assert.AreEqual("the message", parsedMsg.Message);
        }

        [TestMethod]
        public void TestStructuredDataEscapes()
        {
            var parser = SyslogMessageParser.CreateDefault();

            // RFC-5424 section 6.3.3: only \" \\ and \] are escapes; any other backslash is an ordinary character
            foreach (var (escaped, expected) in new[]
            {
                (@"C:\temp\new", @"C:\temp\new"),
                (@"a\""b\\c\]d", @"a""b\c]d"),
                (@"ends with \\", @"ends with \"),
            })
            {
                var text = $"<174>1 - Durotar Orgrimmar - - [a@1 v=\"{escaped}\"] msg";
                var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });
                Assert.AreEqual(expected, parsedMsg.StructuredData5424["a@1"][0].Value, text);
                Assert.AreEqual("msg", parsedMsg.Message, text);
            }
        }

        [TestMethod]
        public void TestTimestampIsReadTheSameInEveryCulture()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<174>1 2026-10-20T12:00:00.123456+09:00 Durotar Orgrimmar - - - msg";
            var expected = new DateTime(2026, 10, 20, 3, 0, 0, DateTimeKind.Utc).AddTicks(1234560);
            var culture = System.Globalization.CultureInfo.CurrentCulture;
            try
            {
                foreach (var name in new[] { "th-TH", "ar-SA", "fa-IR", "ja-JP", "en-US" })
                {
                    System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo(name);
                    var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });
                    Assert.AreEqual(expected, parsedMsg.Header.Timestamp, name);
                    Assert.AreEqual(DateTimeKind.Utc, parsedMsg.Header.Timestamp!.Value.Kind, name);
                }
            }
            finally
            {
                System.Globalization.CultureInfo.CurrentCulture = culture;
            }
        }

        private static readonly string[] MonthNames = System.Globalization.CultureInfo.InvariantCulture.DateTimeFormat.AbbreviatedMonthNames;

        [TestMethod]
        public void TestRfc3164TimeWithoutZoneIsTheReceiversLocalTime()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var now = DateTime.UtcNow;
            var text = $"<13>{MonthNames[now.Month - 1]}  1 12:00:00 Durotar app: msg";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = now, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual(new DateTime(now.Year, now.Month, 1, 12, 0, 0, DateTimeKind.Local).ToUniversalTime(), parsedMsg.Header.Timestamp);
            Assert.AreEqual(DateTimeKind.Utc, parsedMsg.Header.Timestamp!.Value.Kind);
        }

        [TestMethod]
        public void TestRfc3164TimeWithZoneIsConverted()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var now = DateTime.UtcNow;
            var month = MonthNames[now.Month - 1];

            foreach (var (text, offset) in new[]
            {
                ($"<13>{month}  4 17:21:18 JST: Durotar app: msg", TimeSpan.FromHours(9)),
                ($"<13>{month}  4 17:21:18 PST: Durotar app: msg", TimeSpan.FromHours(-8)),
                ($"<186>: {now.Year} {month}  4 17:21:18.183 UTC: Durotar app: msg", TimeSpan.Zero),
                ($"<186>: {now.Year} {month}  4 17:21:18.183 PST: Durotar app: msg", TimeSpan.FromHours(-8)),
            })
            {
                var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = now, SourceIpAddress = IPAddress.Loopback, Message = text });
                var clock = new DateTime(now.Year, now.Month, 4, 17, 21, 18).AddMilliseconds(text.Contains(".183") ? 183 : 0);
                Assert.AreEqual(DateTime.SpecifyKind(clock - offset, DateTimeKind.Utc), parsedMsg.Header.Timestamp, text);
            }
        }

        [TestMethod]
        public void TestRfc3164MonthAheadOfNowIsLastYears()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var now = DateTime.UtcNow;
            // two months ahead of now, as a December entry is in January
            var month = (now.Month + 1) % 12 + 1;
            var expectedYear = month > now.Month ? now.Year - 1 : now.Year;
            var text = $"<13>{MonthNames[month - 1]} 15 12:00:00 Durotar app: msg";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = now, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual(expectedYear, parsedMsg.Header.Timestamp!.Value.ToLocalTime().Year, text);
        }

        [TestMethod]
        public void TestRfc3164TagIsTheAppName()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var month = MonthNames[DateTime.UtcNow.Month - 1];

            foreach (var (text, appName, procId, message) in new[]
            {
                ($"<13>{month}  1 12:00:00 Durotar sshd[4242]: Accepted publickey", "sshd", "4242", "Accepted publickey"),
                ($"<13>{month}  1 12:00:00 Durotar su: session opened", "su", null, "session opened"),
            })
            {
                var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });
                Assert.AreEqual(PayloadType.Rfc3164, parsedMsg.PayloadType, text);
                Assert.AreEqual("Durotar", parsedMsg.Header.HostName, text);
                Assert.AreEqual(appName, parsedMsg.Header.AppName, text);
                Assert.AreEqual(procId, parsedMsg.Header.ProcId, text);
                Assert.AreEqual(message, parsedMsg.Message, text);
            }
        }

        [TestMethod]
        public void TestKeyValueTimeIsTheReceiversLocalTimeInUtc()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<13>device_id=Durotar date=2026-10-20 time=12:00:00 status=ready";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual(PayloadType.KeyValuePairs, parsedMsg.PayloadType);
            Assert.AreEqual(new DateTime(2026, 10, 20, 12, 0, 0, DateTimeKind.Local).ToUniversalTime(), parsedMsg.Header.Timestamp);
            Assert.AreEqual(DateTimeKind.Utc, parsedMsg.Header.Timestamp!.Value.Kind);
        }

        [TestMethod]
        public void TestMalformedStructuredDataIsKeptInMessage()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<174>1 - Durotar Orgrimmar - - [a@1 b=\"c\"][d@1 e=\"unterminated] the message";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual("Orgrimmar", parsedMsg.Header.AppName);
            Assert.IsEmpty(parsedMsg.StructuredData5424);
            Assert.AreEqual("[a@1 b=\"c\"][d@1 e=\"unterminated] the message", parsedMsg.Message);
            Assert.IsNotEmpty(parsedMsg.ErrorMessages);
        }

        [TestMethod]
        public void TestRepeatedStructuredDataIdKeepsEveryParameter()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var text = "<174>1 - Durotar Orgrimmar - - [a@1 b=\"1\"][x@1 y=\"2\"][a@1 c=\"3\"] msg";

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            CollectionAssert.AreEqual(new[] { "b=1", "c=3" }, parsedMsg.StructuredData5424["a@1"].Select(p => p.Name + "=" + p.Value).ToArray());
            Assert.AreEqual("2", parsedMsg.StructuredData5424["x@1"][0].Value);
        }

        [TestMethod]
        public void TestLargeStructuredDataValueParsesInLinearTime()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var value = string.Concat(Enumerable.Repeat(@"{\""key\"":\""value\""},", 20000));
            var text = $"<174>1 - Durotar Orgrimmar - - [gravio@19654 attrs=\"{value}\"] msg";
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text });

            Assert.AreEqual(value.Replace(@"\""", @""""), parsedMsg.StructuredData5424["gravio@19654"][0].Value);
            Assert.IsLessThan(1000, stopwatch.ElapsedMilliseconds, "a 480 KB value with 80,000 escapes");
        }

        [TestMethod]
        public void TestVariantParserFailureKeepsText()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var receivedOn = new DateTime(2026, 10, 21, 1, 2, 3, DateTimeKind.Utc);

            // The key-value parser throws on an unterminated quote; the message is kept as plain text with the error recorded
            var parsedMsg = parser.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = "<14>abc=\"unterminated" });
            Assert.AreEqual(PayloadType.PlainText, parsedMsg.PayloadType);
            Assert.AreEqual(Facility.UserLevel, parsedMsg.Facility);
            Assert.AreEqual(Severity.Informational, parsedMsg.Severity);
            Assert.AreEqual(receivedOn, parsedMsg.Header.Timestamp);
            Assert.AreEqual("abc=\"unterminated", parsedMsg.Message);
            Assert.IsEmpty(parsedMsg.ExtractedTuples);
            Assert.IsNotEmpty(parsedMsg.ErrorMessages);
        }

        private static string[] StructuredDataOf(ParsedSyslogMessage msg) =>
            [.. msg.StructuredData5424.SelectMany(e => e.Value.Select(p => e.Key + "/" + p.Name + "=" + p.Value))];

        private static string[] PairsOf(IEnumerable<NameValuePair> pairs) => [.. pairs.Select(p => p.Name + "=" + p.Value)];

        [TestMethod]
        public void TestWithoutExtractDataTheParseIsTheSameAndDataIsEmpty()
        {
            var extracting = SyslogMessageParser.CreateDefault();
            var notExtracting = SyslogMessageParser.CreateDefault(extractData: false);
            Assert.IsTrue(extracting.ExtractData);
            Assert.IsTrue(new SyslogMessageParser().ExtractData);
            Assert.IsFalse(notExtracting.ExtractData);
            var month = MonthNames[DateTime.UtcNow.Month - 1];

            foreach (var (text, payloadType) in new[]
            {
                ("<174>1 2026-10-20T03:00:00.123456Z Durotar Orgrimmar 21372 ID47 [gravio@19654 peer=\"10.0.0.7\" zone=\"Valley of Strength\"][origin ip=\"10.0.0.8\"] Lok'tar ogar from 10.0.0.9", PayloadType.Rfc5424),
                ($"<13>{month}  1 12:00:00 Durotar sshd[4242]: Accepted publickey for thrall from 10.0.0.7 port 22", PayloadType.Rfc3164),
                ("<14>For the Horde, said 10.0.0.7 and 2234:23d5:e0:25a3::55", PayloadType.PlainText),
                ("<13>device_id=Durotar date=2026-10-20 time=12:00:00 src=10.0.0.7 status=ready", PayloadType.KeyValuePairs),
            })
            {
                var receivedOn = DateTime.UtcNow;
                var on = extracting.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = text });
                var off = notExtracting.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = text });

                Assert.AreEqual(payloadType, on.PayloadType, text);
                Assert.AreEqual(payloadType, off.PayloadType, text);
                Assert.AreEqual(on.Facility, off.Facility, text);
                Assert.AreEqual(on.Severity, off.Severity, text);
                // the plain-text parser stamps the time it parses, so two parses of one record differ there
                if (payloadType != PayloadType.PlainText)
                {
                    Assert.AreEqual(on.Header.Timestamp, off.Header.Timestamp, text);
                }
                Assert.AreEqual(on.Header.HostName, off.Header.HostName, text);
                Assert.AreEqual(on.Header.AppName, off.Header.AppName, text);
                Assert.AreEqual(on.Header.ProcId, off.Header.ProcId, text);
                Assert.AreEqual(on.Header.MsgId, off.Header.MsgId, text);
                Assert.AreEqual(on.Header.Version, off.Header.Version, text);
                Assert.AreEqual(on.Message, off.Message, text);
                CollectionAssert.AreEqual(StructuredDataOf(on), StructuredDataOf(off), text);
                Assert.IsEmpty(on.ErrorMessages, text);
                Assert.IsEmpty(off.ErrorMessages, text);

                Assert.IsNotEmpty(on.Data, text);
                Assert.IsEmpty(off.Data, text);
                CollectionAssert.AreEqual(PairsOf(on.ExtractedTuples.Where(p => p.Name is not ("IPv4" or "IPv6"))), PairsOf(off.ExtractedTuples), text);
            }

            var keyValue = notExtracting.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = "<13>device_id=Durotar src=10.0.0.7" });
            CollectionAssert.AreEqual(new[] { "device_id=Durotar", "src=10.0.0.7" }, PairsOf(keyValue.ExtractedTuples));

            // an initializer sets it too, and it skips the extractors the parser was given
            var initialized = new SyslogMessageParser { ExtractData = false };
            initialized.AddVariantParsers(new Rfc3164SyslogParser());
            initialized.AddValueExtractors(new IpAddressesExtractor());
            var rfc3164 = initialized.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = $"<13>{month}  1 12:00:00 Durotar sshd[4242]: Accepted publickey from 10.0.0.7" });
            Assert.AreEqual("Accepted publickey from 10.0.0.7", rfc3164.Message);
            Assert.IsEmpty(rfc3164.ExtractedTuples);
            Assert.IsEmpty(rfc3164.Data);
        }

        [TestMethod]
        public void TestDefaultParserExtractsIpAddressesAndMergesData()
        {
            var parser = SyslogMessageParser.CreateDefault();
            var month = MonthNames[DateTime.UtcNow.Month - 1];

            // RFC-5424: the IP addresses among the SD values, not in MSG, and every SD parameter
            var rfc5424 = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = "<174>1 - Durotar Orgrimmar - - [gravio@19654 peer=\"10.0.0.7\" zone=\"Valley of Strength\"][origin ip=\"10.0.0.8\"] from 10.0.0.9" });
            CollectionAssert.AreEqual(new[] { "IPv4=10.0.0.7", "IPv4=10.0.0.8" }, PairsOf(rfc5424.ExtractedTuples));
            CollectionAssert.AreEquivalent(new[] { "IPv4", "peer", "zone", "ip" }, rfc5424.Data.Keys.ToArray());
            CollectionAssert.AreEqual(new[] { "10.0.0.7", "10.0.0.8" }, (string[])rfc5424.Data["IPv4"]);
            Assert.AreEqual("Valley of Strength", rfc5424.Data["zone"]);

            // RFC-3164: the IP addresses in MSG, always an array
            var rfc3164 = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = $"<13>{month}  1 12:00:00 Durotar sshd[4242]: Accepted publickey from 10.0.0.7" });
            CollectionAssert.AreEqual(new[] { "IPv4=10.0.0.7" }, PairsOf(rfc3164.ExtractedTuples));
            CollectionAssert.AreEqual(new[] { "10.0.0.7" }, (string[])rfc3164.Data["IPv4"]);

            // key-value: the pairs, then the IP addresses among their values
            var keyValue = parser.Parse(new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = "<13>device_id=Durotar src=10.0.0.7" });
            CollectionAssert.AreEqual(new[] { "device_id=Durotar", "src=10.0.0.7", "IPv4=10.0.0.7" }, PairsOf(keyValue.ExtractedTuples));
            Assert.AreEqual("Durotar", keyValue.Data["device_id"]);
            CollectionAssert.AreEqual(new[] { "10.0.0.7" }, (string[])keyValue.Data["IPv4"]);
        }

        [TestMethod]
        public void TestAParserWithNoVariantParsersRefusesToParse()
        {
            var empty = new SyslogMessageParser();

            foreach (var text in new[] { "<14>For the Horde", "no prefix at all" })
            {
                var raw = new RawSyslogMessage() { ReceivedOn = DateTime.UtcNow, SourceIpAddress = IPAddress.Loopback, Message = text };
                Assert.ThrowsExactly<InvalidOperationException>(() => empty.Parse(raw), text);
                Assert.IsFalse(empty.TryParse(raw, out var parsed), text);
                Assert.IsNull(parsed, text);
            }
        }

        [TestMethod]
        public void TestTheDefaultParserSetCanBeBuiltFromPublicTypes()
        {
            var byDefault = SyslogMessageParser.CreateDefault();
            var rebuilt = new SyslogMessageParser();
            rebuilt.AddVariantParsers(new Rfc5424SyslogParser(), new KeyValueListParser(), new Rfc3164SyslogParser(), new PlainTextParser());
            rebuilt.AddValueExtractors(new IpAddressesExtractor());
            CollectionAssert.AreEqual(byDefault.VariantParsers.Select(p => p.GetType()).ToArray(), rebuilt.VariantParsers.Select(p => p.GetType()).ToArray());
            CollectionAssert.AreEqual(byDefault.ValueExtractors.Select(e => e.GetType()).ToArray(), rebuilt.ValueExtractors.Select(e => e.GetType()).ToArray());

            var month = MonthNames[DateTime.UtcNow.Month - 1];
            foreach (var (text, payloadType) in new[]
            {
                ("<174>1 2026-10-20T03:00:00.123456Z Durotar Orgrimmar 21372 ID47 [gravio@19654 peer=\"10.0.0.7\"] Lok'tar ogar", PayloadType.Rfc5424),
                ($"<13>{month}  1 12:00:00 Durotar sshd[4242]: Accepted publickey from 10.0.0.7", PayloadType.Rfc3164),
                ("<13>device_id=Durotar date=2026-10-20 time=12:00:00 src=10.0.0.7", PayloadType.KeyValuePairs),
                ("<14>For the Horde, said 10.0.0.7", PayloadType.PlainText),
            })
            {
                var receivedOn = DateTime.UtcNow;
                var expected = byDefault.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = text });
                var actual = rebuilt.Parse(new RawSyslogMessage() { ReceivedOn = receivedOn, SourceIpAddress = IPAddress.Loopback, Message = text });

                Assert.AreEqual(payloadType, actual.PayloadType, text);
                Assert.AreEqual(expected.Header.Timestamp, actual.Header.Timestamp, text);
                Assert.AreEqual(expected.Header.HostName, actual.Header.HostName, text);
                Assert.AreEqual(expected.Header.AppName, actual.Header.AppName, text);
                Assert.AreEqual(expected.Message, actual.Message, text);
                CollectionAssert.AreEqual(StructuredDataOf(expected), StructuredDataOf(actual), text);
                CollectionAssert.AreEqual(PairsOf(expected.ExtractedTuples), PairsOf(actual.ExtractedTuples), text);
                Assert.IsNotEmpty(actual.ExtractedTuples, text);
                Assert.IsEmpty(actual.ErrorMessages, text);
            }
        }

    }
}
