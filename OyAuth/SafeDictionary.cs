using System.Collections.Concurrent;
using System.Collections.Generic;

namespace OyAuth {
  internal class SafeDictionary<K, T> : ConcurrentDictionary<K, T> {
    public SafeDictionary() { }
    public SafeDictionary(IEqualityComparer<K> comparer) : base(comparer) { }
    public virtual new T this[K key] {
      get {
        T value;
        if (TryGetValue(key, out value))
          return value;
        else return default(T);
      }
      set {
        if (value == null)
          Remove(key);
        else
          AddOrUpdate(key, value, UpdateFactory);
      }
    }

    private static T UpdateFactory(K key, T value) {
      return value;
    }

    public bool Remove(K key) {
      T value;
      return TryRemove(key, out value);
    }

    public void Add(K key, T value) {
      this[key] = value;
    }
  }
}
