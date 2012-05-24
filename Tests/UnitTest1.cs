using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Should.Fluent;

namespace OyAuth.Tests {
  [TestClass]
  public class UnitTest1 {
    public TestContext TestContext { get; set; }

    [TestMethod]
    public void ValidateSignatures() {
      OAuth.MaxNonceAge = TimeSpan.FromDays(365 * 10);

      string authHeader = "OAuth realm=\"https://api.tripit.com\",oauth_nonce=\"39100e296c709a592600c8d1a3ee69dd\",oauth_timestamp=\"1235272437\",oauth_consumer_key=\"5dbf348aa966c5f7f07e8ce2ba5e7a3badc234bc\",oauth_signature_method=\"HMAC-SHA1\",oauth_version=\"1.0\",oauth_signature=\"KlTlU95CdzFYo5tfrJjaPz5RA6g%3D\"";
      var path = "https://api.tripit.com/oauth/request_token";
      var secret = "fceb3aedb960374e74f559caeabab3562efe97b4";
      var form = string.Empty;
      OAuth.Validate("POST", path, form, authHeader, OAuth.MaxNonceAge.TotalSeconds, key => secret, true);

      // http://oauth.googlecode.com/svn/code/javascript/example/signature.html
      authHeader = "OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"abcd\",oauth_timestamp=\"1337880056\",oauth_nonce=\"uvaH8OlEQZO\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"CvsqEeMIzh51f1D5QfpDiVt8F7I%3D\"";
      form = "access=tested&Name=test+tested tester";
      path = "http://host.net/resource";
      secret = "efgh";
      OAuth.Validate("POST", path, form, authHeader, OAuth.MaxNonceAge.TotalSeconds, key => secret, true);
    }

    [TestMethod]
    public void ParseQueryString() {
      var query = new OyAuth.Utilities.Query("http://test/?id=0&id=1&another=test", string.Empty);
      query["id"].Should().Equal("0,1");
      query["another"].Should().Equal("test");

      query = new OyAuth.Utilities.Query(string.Empty, "id=0&id=1&another=test");
      query["id"].Should().Equal("0,1");
      query["another"].Should().Equal("test");
    }

    [TestMethod]
    public void DiscoverGoogleOpenIDServer() {
      var info = OpenID.GetIdentityServer("https://www.google.com/accounts/o8/id".ToUri()).ToArray();
      var server = info.FirstOrDefault();
      server.Should().Not.Be.Null();
      server.Server.ToString().Should().Equal("https://www.google.com/accounts/o8/ud");
    }

    [TestMethod]
    public void DiscoverYahooOpenIDServer() {
      var info = OpenID.GetIdentityServer("http://www.yahoo.com/".ToUri()).ToArray();
      var server = info.FirstOrDefault();
      server.Should().Not.Be.Null();
      server.Server.ToString().Should().Equal("https://open.login.yahooapis.com/openid/op/auth");
    }
  }
}
