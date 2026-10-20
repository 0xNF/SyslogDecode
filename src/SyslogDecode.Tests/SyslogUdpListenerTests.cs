// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/

namespace SyslogDecode.Tests
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using SyslogDecode.Model;
    using SyslogDecode.Udp;

    [TestClass]
    public class SyslogUdpListenerTests
    {
        [TestMethod]
        public void TestStopRaisesNoError()
        {
            using var listener = new SyslogUdpListener(IPAddress.Loopback, 0);
            int errors = 0;
            listener.Error += (s, e) => Interlocked.Increment(ref errors);
            listener.Start();
            Thread.Sleep(100); // let the listener thread block in Receive
            listener.Stop();
            Assert.AreEqual(0, errors);
        }

        [TestMethod]
        public void TestStopReturnsAfterListenerThreadFailed()
        {
            using var listener = new SyslogUdpListener(IPAddress.Loopback, 0);
            using var failed = new ManualResetEventSlim();
            listener.Error += (s, e) => failed.Set();
            listener.Subscribe(new ThrowingObserver());
            listener.Start();
            var endPoint = (IPEndPoint)listener.PortListener!.Client.LocalEndPoint!;
            using var sender = new UdpClient();

            sender.Send(Encoding.UTF8.GetBytes("<14>first"), endPoint);
            Assert.IsTrue(failed.Wait(TimeSpan.FromSeconds(5)), "The listener thread did not fail.");

            // A datagram no thread will read stays in the buffer
            sender.Send(Encoding.UTF8.GetBytes("<14>second"), endPoint);
            Assert.IsTrue(SpinWait.SpinUntil(() => listener.GetUdpBufferBytesAvailable() > 0, TimeSpan.FromSeconds(5)), "The second datagram did not arrive.");
            Assert.IsTrue(Task.Run(listener.Stop).Wait(TimeSpan.FromSeconds(5)), "Stop did not return.");
        }

        class ThrowingObserver : IObserver<RawSyslogMessage>
        {
            public void OnNext(RawSyslogMessage value) => throw new InvalidOperationException("observer failed");

            public void OnError(Exception error)
            {
            }

            public void OnCompleted()
            {
            }
        }
    }
}
