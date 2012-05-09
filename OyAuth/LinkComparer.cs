using System;
using System.Collections.Generic;

namespace OyAuth {
  public class LinkComparer : IEqualityComparer<string>, IEqualityComparer<Uri> {
    public static readonly LinkComparer Instance = new LinkComparer();
    public static readonly LinkComparer Host = new LinkComparer { _CompareHostOnly = true };

    private bool _CompareHostOnly = false;

    public bool Equals(string x, string y) {
      if (_CompareHostOnly)
        return Link.NormalizeHost(x) == Link.NormalizeHost(y);
      return Link.Normalize(x) == Link.Normalize(y);
    }

    public int GetHashCode(string obj) {
      return Link.Normalize(obj).GetHashCode();
    }

    public bool Equals(Uri x, Uri y) {
      return Equals(x.ToString(), y.ToString());
    }

    public int GetHashCode(Uri obj) {
      return Link.Normalize(obj.ToString()).GetHashCode();
    }
  }
}