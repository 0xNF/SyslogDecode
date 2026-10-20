// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/


namespace SyslogDecode.Tests
{
    using System;
    using System.Linq;
    using System.Net;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using SyslogDecode.Parsing;
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

    }
}
