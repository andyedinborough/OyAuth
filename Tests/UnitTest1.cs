using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Should.Fluent;

namespace OyAuth.Tests {
  [TestClass]
  public class UnitTest1 {
    public TestContext TestContext { get; set; }


    [TestMethod]
    public void ParseQueryString() {
      var query = OyAuth.Utilities.ParseQueryString("http://test/?id=0&id=1&another=test");
      query["id"].Should().Equal("0,1");
      query["another"].Should().Equal("test");

      query = OyAuth.Utilities.ParseQueryString(string.Empty, "id=0&id=1&another=test");
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
