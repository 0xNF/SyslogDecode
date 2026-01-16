// /********************************************************
// *                                                       *
// *   Copyright (C) Microsoft. All rights reserved.       *
// *                                                       *
// ********************************************************/


namespace SyslogDecode.Common
{
    /// <summary>
    ///     Base class for components implementing the <see cref="IObservable{T}" /> interface.
    /// </summary>
    /// <typeparam name="T">The data type.</typeparam>
    /// <remarks>Provides sync and async broadcast mode.</remarks>
    public class Observable<T> : IObservable<T>
    {
        /// <summary>Constructs a new instance. </summary>
        public Observable()
        {
        }

        // We use copy, add/remove, replace method when adding/removing subscriptions
        // As a benefit, when we call OnNext on each subscriber, we iterate the list without locks
        private IList<Subscription> _subscriptions = [];
        private readonly Lock _lock = new();

        #region IObservable implementation

        /// <summary>Subscribes an observer. </summary>
        /// <param name="observer">An observer instance.</param>
        /// <returns>A disposable subscription object. Disposing the object cancels the subscription.</returns>
        public IDisposable Subscribe(IObserver<T> observer)
        {
            return AddSubscription(observer);
        }

        #endregion

        /// <summary>Unsubscribes an observer. </summary>
        /// <param name="observer">An observer instance.</param>
        public void Unsubscribe(IObserver<T> observer)
        {
            RemoveSubscription(observer);
        }

        /// <summary>Broadcasts data. Calls the OnNext method of all subscribed observers. </summary>
        /// <param name="item">Data to broadcast.</param>
        /// <remarks>The subscribers are notified according to the broadcast mode - in sync or async manner.</remarks>
        public virtual void Broadcast(T item)
        {
            IList<Subscription> sList = _subscriptions;
            for (int i = 0; i < sList.Count; i++)
            {
                sList[i].Observer.OnNext(item);
            }
        }

        /// <summary>Broadcasts an error. Calls OnError method of all subscribers passing the exception as a parameter. </summary>
        /// <param name="error">The exception to broadcast.</param>
        protected virtual void BroadcastError(Exception error)
        {
            IList<Subscription> sList = _subscriptions;
            for (int i = 0; i < sList.Count; i++)
            {
                sList[i].Observer.OnError(error);
            }
        }

        /// <summary>Calls OnCompleted method of all subscribers. </summary>
        protected void BroadcastOnCompleted()
        {
            IList<Subscription> sList = _subscriptions;
            for (int i = 0; i < sList.Count; i++)
            {
                sList[i].Observer.OnCompleted();
            }
        }

        // Subscription list operations
        // We use copy, add/remove, replace method when adding/removing subscriptions
        // As a benefit, when we call OnNext on each subscriber, we iterate the list without locks
        private Subscription AddSubscription(IObserver<T> observer)
        {
            lock (_lock)
            {
                List<Subscription> newList = [.. _subscriptions];
                Subscription subscr = new() { Observable = this, Observer = observer };
                newList.Add(subscr);
                _ = Interlocked.Exchange(ref _subscriptions, newList);
                return subscr;
            }
        }

        private void RemoveSubscription(IObserver<T> observer)
        {
            lock (_lock)
            {
                List<Subscription> newList = [.. _subscriptions];
                Subscription? subscr = newList.FirstOrDefault(s => s.Observer == observer);
                if (subscr != null)
                {
                    _ = newList.Remove(subscr);
                    _ = Interlocked.Exchange(ref _subscriptions, newList);
                }
            }
        }

        /// <summary>Represents a subscription for an observable source. </summary>
        internal class Subscription : IDisposable
        {
            public required Observable<T> Observable;
            public required IObserver<T> Observer;

            public void Dispose()
            {
                Observable.Unsubscribe(Observer);
            }
        }

    } //class
}