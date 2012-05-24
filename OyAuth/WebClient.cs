
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;

namespace OyAuth {
  public class InvalidContentTypeException : System.Exception {
    public InvalidContentTypeException(System.Net.WebRequest req, System.Net.WebResponse res) {
      Response = (System.Net.HttpWebResponse)res;
      Request = (System.Net.HttpWebRequest)req;
    }
    public System.Net.HttpWebResponse Response { get; private set; }
    public System.Net.HttpWebRequest Request { get; private set; }
    public string ContentType {
      get { return Response.ContentType ?? string.Empty; }
    }
  }

  /// <summary>
  /// Adds some additional options to System.Net.WebClient
  /// </summary>
  /// <remarks></remarks>
  public class WebClient : System.Net.WebClient {
    public WebClient() {
      Cookies = new CookieContainer();
      Encoding = System.Text.Encoding.UTF8;
      SuppressInvalidStatusCode = true;
    }

    /// <summary>
    /// Timeout in seconds
    /// </summary>
    public int Timeout { get; set; }

    public string UserAgent { get; set; }
    public string Referer { get; set; }
    public bool KeepAlive { get; set; }
    public string[] ValidContentTypes { get; set; }
    public string ContentType { get; set; }
    public DateTime? IfModifiedSince { get; set; }
    public bool SuppressInvalidStatusCode { get; set; }

    public CookieContainer Cookies { get; set; }

    public event Action<Uri, System.Net.HttpWebRequest> OnGetWebRequest;

    private Uri _Url;
    public Uri Url {
      get { return _Url; }
    }

    protected override System.Net.WebRequest GetWebRequest(System.Uri address) {
      _Url = address;

      var basereq = base.GetWebRequest(address);
      System.Net.HttpWebRequest req = basereq as System.Net.HttpWebRequest;
      if (req != null) {
        if (ContentType != null) req.ContentType = ContentType;
        req.AllowAutoRedirect = false;
        req.CookieContainer = Cookies;
        req.AutomaticDecompression = System.Net.DecompressionMethods.GZip | DecompressionMethods.Deflate;
        if (Timeout > 0) req.Timeout = Timeout * 1000;
        if (!Referer.IsNullOrEmpty()) req.Referer = Referer;
        if (!UserAgent.IsNullOrEmpty()) req.UserAgent = UserAgent;
        if (IfModifiedSince != null) req.IfModifiedSince = IfModifiedSince.Value;
        req.KeepAlive = KeepAlive;

        req.Accept = Headers[HttpRequestHeader.Accept].NotEmpty(Headers["accept"], req.Accept);

        if (OnGetWebRequest != null) {
          OnGetWebRequest(address, req);
        }
      }
      return basereq;
    }

    private Collection<Uri> _Locations = new Collection<Uri>();
    public Collection<Uri> Locations {
      get { return _Locations; }
    }

    public System.Net.HttpStatusCode StatusCode { get; private set; }

    public event Action<System.Net.WebRequest, System.Net.WebResponse> OnGetWebResponse;
    protected override System.Net.WebResponse GetWebResponse(System.Net.WebRequest request) {
      int redirected = 0;
      System.Net.WebResponse baseresp;
      _Locations.Clear();

      do {
        _Locations.Add(_Url);
        try {
          baseresp = base.GetWebResponse(request);
        } catch (WebException ex) {
          if (!SuppressInvalidStatusCode) throw;
          baseresp = ex.Response;
        }

        var resp = baseresp as System.Net.HttpWebResponse;
        if (resp == null) return baseresp;
        StatusCode = resp.StatusCode;

        if (resp.Headers[HttpResponseHeader.Location].IsNullOrEmpty()) {
          redirected = 0;
        } else {
          //Referer = request.RequestUri.ToString();
          _Url = new Uri(request.RequestUri, resp.Headers[HttpResponseHeader.Location].Replace("&amp%3B", "&"));
          // Headers.Remove(HttpRequestHeader.ContentLength);
          request = GetWebRequest(_Url);
          var req = request as System.Net.HttpWebRequest;
          req.ContentLength = 0;
          req.Method = "GET";

          redirected += 1;
        }
      }
      while (redirected > 0 & redirected < 15);

      var ct = baseresp.ContentType.NotNull();
      if (!ValidContentTypes.IsNullOrEmpty() && !ValidContentTypes.Any(x => ct.Contains(x, StringComparison.OrdinalIgnoreCase)))
        throw new InvalidContentTypeException(request, baseresp);

      if (OnGetWebResponse != null) {
        OnGetWebResponse(request, baseresp);
      }
      Referer = _Url.ToString();
      return baseresp;
    }
  }
}