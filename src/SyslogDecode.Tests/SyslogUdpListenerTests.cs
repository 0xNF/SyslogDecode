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

        [TestMethod]
        public void TestADatagramArrivingAfterSeveralIdlePollsIsReceived()
        {
            using var listener = new SyslogUdpListener(IPAddress.Loopback, 0);
            using var received = new ManualResetEventSlim();
            string message = null;
            listener.Received += (s, e) =>
            {
                message = e.Item.Message;
                received.Set();
            };
            listener.Start();
            var endPoint = (IPEndPoint)listener.PortListener!.Client.LocalEndPoint!;
            using var sender = new UdpClient();

            Thread.Sleep(3 * SyslogUdpListener.ReceivePollInterval);
            sender.Send(Encoding.UTF8.GetBytes("<14>Lok'tar ogar"), endPoint);

            Assert.IsTrue(received.Wait(TimeSpan.FromSeconds(5)), "The datagram was not received.");
            Assert.AreEqual("<14>Lok'tar ogar", message);
            Assert.IsTrue(Task.Run(listener.Stop).Wait(listener.DrainTimeout + 2 * SyslogUdpListener.ReceivePollInterval), "Stop did not return.");
        }

        [TestMethod]
        public void TestClosingTheSocketUnderARunningListenerRaisesError()
        {
            using var listener = new SyslogUdpListener(IPAddress.Loopback, 0);
            using var failed = new ManualResetEventSlim();
            Exception error = null;
            listener.Error += (s, e) =>
            {
                error = e.Error;
                failed.Set();
            };
            listener.Start();
            Thread.Sleep(100); // let the listener thread wait for a datagram

            Assert.IsTrue(Task.Run(listener.PortListener!.Close).Wait(TimeSpan.FromSeconds(5)), "Close did not return.");

            Assert.IsTrue(failed.Wait(TimeSpan.FromSeconds(5)), "The listener raised no error.");
            Assert.IsTrue(error is ObjectDisposedException or SocketException, error.ToString());
        }

        [TestMethod]
        public void TestASocketClosedBeforeTheListenerStartsRaisesObjectDisposed()
        {
            using var listener = new SyslogUdpListener(IPAddress.Loopback, 0);
            using var failed = new ManualResetEventSlim();
            Exception error = null;
            listener.Error += (s, e) =>
            {
                error = e.Error;
                failed.Set();
            };

            listener.PortListener!.Close();
            listener.Start();

            Assert.IsTrue(failed.Wait(TimeSpan.FromSeconds(5)), "The listener raised no error.");
            Assert.IsInstanceOfType<ObjectDisposedException>(error, error.ToString());
            listener.Stop();
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
