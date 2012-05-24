using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace OyAuth {
  public static class OAuth {
    private const string _UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
    public const string HMACSHA1 = "HMAC-SHA1";

    private static TimeSpan _MaxNonceAge = TimeSpan.FromMinutes(5);
    public static TimeSpan MaxNonceAge {
      get { return _MaxNonceAge; }
      set {
        _MaxNonceAge = value;
        var max = 2 ^ 32 - 2;
        if (_MaxNonceAge.TotalMilliseconds > max) {
          _Cleanup.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
        } else {
          _Cleanup.Change(_MaxNonceAge, _MaxNonceAge);

        }
      }
    }
    private static readonly SafeDictionary<string, DateTime> _NonceCache = new SafeDictionary<string, DateTime>();
    private static readonly System.Threading.Timer _Cleanup = new System.Threading.Timer(state => {
      lock (_Cleanup) {
        var keys = _NonceCache.Where(x => x.Value.Add(MaxNonceAge) < DateTime.UtcNow).Select(x => x.Key).ToArray();
        DateTime value;
        foreach (var key in keys)
          _NonceCache.TryRemove(key, out value);
      }
    }, null, MaxNonceAge, MaxNonceAge);

    public static string GetNonce(int length = 20) {
      var random = new Random();
      string nonce;
      while (true) {
        nonce = string.Empty;
        while (nonce.Length < length) {
          nonce += _UnreservedChars[random.Next(0, 63)];
        }

        if (!_NonceCache.ContainsKey(nonce)) {
          _NonceCache.TryAdd(nonce, DateTime.UtcNow);
          return nonce;
        }
      }
    }

    public static bool Validate(System.Web.HttpRequestBase request, double numSecondsValid, Func<string, string> GetConsumerSecret, bool throwOnError = false) {
      return Validate(request.HttpMethod, request.Url.ToString(), request.Form.ToString(), request.Headers["Authorization"], numSecondsValid, GetConsumerSecret, throwOnError);
    }
    public static bool Validate(System.Web.HttpRequest request, double numSecondsValid, Func<string, string> GetConsumerSecret, bool throwOnError = false) {
      return Validate(request.HttpMethod, request.Url.ToString(), request.Form.ToString(), request.Headers["Authorization"], numSecondsValid, GetConsumerSecret, throwOnError);
    }

    public static bool Validate(string url, Func<string, string> GetConsumerSecret) {
      return Validate(null, url, null, null, 90, GetConsumerSecret);
    }

    public static bool Validate(string method, string url, string posted, string authorizationHeader, double numSecondsValid, Func<string, string> GetConsumerSecret, bool throwOnError = false, Func<string, string, string> GetTokenSecret = null) {
      method = method ?? "GET";

      if (numSecondsValid < 0 || numSecondsValid > MaxNonceAge.TotalSeconds)
        throw new ArgumentException(string.Format("Must be more than 0 and less than {0} seconds", MaxNonceAge.TotalSeconds), "numSecondsValid");

      var query = new Utilities.Query(url, posted);
      if (!authorizationHeader.IsNullOrEmpty()) {
        var authorization = ParseAuthorizationHeader(authorizationHeader);
        authorization.Keys.ForEach(key => query[key] = authorization[key]);
      }

      if (query["oauth_version"] != "1.0") {
        if (throwOnError) throw new System.Web.HttpException(401, "Invalid version specified");
      }

      if (numSecondsValid > 0) {
        double timestamp = query["oauth_timestamp"].ToDouble();
        double diff = Math.Abs(DateTime.UtcNow.GetSecondsSince1970() - timestamp);

        if (diff > numSecondsValid) {
          if (throwOnError) throw new System.Web.HttpException(401, "The timestamp is too old");
          return false;
        }

        DateTime used = _NonceCache[query["oauth_nonce"]];
        if (used.AddSeconds(numSecondsValid) > DateTime.UtcNow) {
          if (throwOnError) throw new System.Web.HttpException(401, "The nonce is not unique");
          return false;
        }
        _NonceCache[query["oauth_nonce"]] = DateTime.UtcNow;
      }

      string hashAlgorithm = query["oauth_signature_method"];
      int q = url.IndexOf('?');
      string path = q == -1 ? url : url.Substring(0, q);

      string secret = GetConsumerSecret(query["oauth_consumer_key"].NotEmpty(query["client_id"]));
      string sig;
      try {
        var querystring = GetQueryString(query, true);
        sig = GetSignature(method, hashAlgorithm, secret, path, querystring, GetTokenSecret != null && query.ContainsKey("oauth_token") ? GetTokenSecret(query["oauth_token"], query["oauth_verifier"]) : null);
      } catch (Exception) {
        if (throwOnError) throw;
        return false;
      }

      var testSig = query["oauth_signature"];
      if (sig != testSig) {
        if (throwOnError)
          throw new System.Web.HttpException(401, string.Format("The signature is invalid. {0}", GetQueryString(query, false)));
        return false;
      }

      return true;
    }


    public static IDictionary<string, string> ParseAuthorizationHeader(string header) {
      while (header.StartsWith("OAuth")) header = header.Substring(5).Trim();

      var result = new Dictionary<string, string>();
      while (header.Length > 0) {
        var eq = header.IndexOf('=');
        if (eq < 0) eq = header.Length;
        var name = header.Substring(0, eq).Trim().Trim(',').Trim();

        var value = header = header.Substring((eq + 1).AtMost(header.Length)).Trim();

        if (value.StartsWith("\"")) {
          ProcessHeaderValue(1, ref header, ref value, '"');
        } else if (value.StartsWith("'")) {
          ProcessHeaderValue(1, ref header, ref value, '\'');
        } else {
          ProcessHeaderValue(0, ref header, ref value, ' ', ',');
        }

        result.SetValue(name, Uri.UnescapeDataString(value));
      }

      return result;
    }

    private static void ProcessHeaderValue(int skip, ref string header, ref string value, params char[] lookFor) {
      var quote = value.IndexOfAny(lookFor, skip);
      if (quote < 0) quote = value.Length;
      header = header.Substring((quote + 1).AtMost(header.Length));
      value = value.Substring(skip, quote - skip);
    }

    private static string GetQueryString(Utilities.Query query, bool encode) {
      return query.ToString(encode, "oauth_signature", "realm");
    }

    public static string GenerateUrl(string url, string consumerKey, string consumerSecret, string method = null, string hashAlgorithm = null, string posted = null, string token = null, string verifier = null, string tokenSecret = null) {
      var result = GetInfo(method, hashAlgorithm, ref url, posted, consumerKey, consumerSecret, token, verifier, tokenSecret);
      var querystring = GetQueryString(result.Item1, true);
      return string.Concat(url, "?", querystring, "&oauth_signature=", result.Item3.UrlEncode());
    }

    public static string GenerateAuthorizationHeader(string url, string consumerKey, string consumerSecret, string method = null, string hashAlgorithm = null, string posted = null, string token = null, string verifier = null, string tokenSecret = null, string realm = null) {
      var result = GetInfo(method, hashAlgorithm, ref url, posted, consumerKey, consumerSecret, token, verifier, tokenSecret);
      result.Item1["oauth_signature"] = result.Item3;
      realm = realm.IsNullOrEmpty() ? url.ToUri().GetLeftPart(UriPartial.Authority) : realm;

      var @params = result.Item1.Where(x => x.Name.StartsWith("oauth_")).OrderBy(x => x.Name)
          .Select(x => string.Format("{0}=\"{1}\"", x.Name, x.Value.UrlEncode())).ToArray();
      return string.Concat("OAuth realm=\"", realm.UrlEncode(), "\", ", string.Join(", ", @params));
    }

    public static Tuple<Utilities.Query, Utilities.Query, string> GetInfo(string method, string hashAlgorithm, ref string url, string posted, string consumerKey, string consumerSecret, string token, string verifier, string tokenSecret) {
      method = method ?? "GET";
      hashAlgorithm = hashAlgorithm ?? HMACSHA1;

      string timestamp = DateTime.UtcNow.GetSecondsSince1970().ToString();
      string nonce = GetNonce();

      var query = new Utilities.Query(url, posted);
      var postedquery = new Utilities.Query(string.Empty, posted);

      int q = url.IndexOf('?');
      if (q > -1) url = url.Substring(0, q);

      //add the oauth stuffs
      query["oauth_consumer_key"] = consumerKey;
      query["oauth_nonce"] = nonce;
      query["oauth_signature_method"] = hashAlgorithm;
      query["oauth_timestamp"] = timestamp;
      query["oauth_version"] = "1.0";
      if (token != null) query["oauth_token"] = token;
      if (verifier != null) query["oauth_verifier"] = verifier;

      //put the querystring back together in alphabetical order
      string querystring = GetQueryString(query, true);
      string sig = GetSignature(method, hashAlgorithm, consumerSecret, url, querystring, tokenSecret);

      return Tuple.Create(query, postedquery, sig);
    }

    private static string GetSignature(string method, string hashAlgorithm, string consumerSecret, string url, string querystring, string tokenSecret) {
      string data = string.Concat(method.ToUpper(), "&", url.UrlEncode(), "&", querystring.UrlEncode());

      string sig;
      using (var hasher = GetHashAglorithm(hashAlgorithm)) {
        hasher.Key = string.Concat(consumerSecret.UrlEncode(), "&", tokenSecret.IsNullOrEmpty() ? null : tokenSecret.UrlEncode()).GetBytes();
        sig = hasher.ComputeHash(data.GetBytes()).ToBase64();
      }

      return sig;
    }

    private static KeyedHashAlgorithm GetHashAglorithm(string name) {
      switch (name) {
        case HMACSHA1: return new HMACSHA1();
        default: throw new NotSupportedException(string.Format("The specified type, {0}, is not supported.", name));
      }
    }
  }
}