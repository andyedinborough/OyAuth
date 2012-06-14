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

			form = "Address=dsdsdsds&City=dsdsdsds&Country=USA&Degrees%5b0%5d.DateCompleted=&Degrees%5b0%5d.Location=&Degrees%5b0%5d.Major=&Degrees%5b0%5d.School=uw&Degrees%5b0%5d.Type=8&Email=hac.jdd@gmail.com&IsDefault=true&JobHistories%5b0%5d.DateEnd=&JobHistories%5b0%5d.DateStart=2012-01-01&JobHistories%5b0%5d.Description=null&JobHistories%5b0%5d.Employer=null&JobHistories%5b0%5d.Location=null&JobHistories%5b0%5d.Title=null&Name=My%2520God&PhoneMobile=258&State=vvvvaaaa&Zip=6688777&access_token=7b7df4fa-8bc7-4a58-baed-81531dd2e5e0";
			path = "http://1apply.com/api/resume/28/edit.json";
			authHeader = "oauth_consumer_key=\"A2E851B5-A287-4EFD-B715-42A6A145206F\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"voHrXSzBHgVw%2FZw4pMPPhCUsaBQ%3D\", oauth_timestamp=\"1337856459\", oauth_nonce=\"7EDD5EF7-4A4A-4D45-A99B-A281437CAC53\", oauth_version=\"1.0\"";
			secret = "IgAX9hMr8txR1kepdl3yzjNi6Oo2nCFHGUcD0PTVLWq7KvBQ";
			OAuth.Validate("POST", path, form, authHeader, OAuth.MaxNonceAge.TotalSeconds, key => secret, true);

			form = "name=value&name=value+value";
			path = "http://host.net/resource";
			authHeader = "OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"abcd\",oauth_timestamp=\"1339684990\",oauth_nonce=\"Qzivxh6r6Nm\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"%2FlR5y6U9RYMIzvnA9%2BizMYznA4k%3D\"";
			secret = "efgh";
			OAuth.Validate("GET", path, form, authHeader, OAuth.MaxNonceAge.TotalSeconds, key => secret, true);
		}

		[TestMethod]
		public void ParseQueryString() {
			var query = new OyAuth.Utilities.Query("http://test/?id=0&id=1&another=test", string.Empty);
			query["id"].Should().Equal("0,1");
			query["another"].Should().Equal("test");

			query = new OyAuth.Utilities.Query(string.Empty, "id=0&id=1&another=test");
			query["id"].Should().Equal("0,1");
			query["another"].Should().Equal("test");

			query = new Utilities.Query(null, "test+test=test+test");
			query["test test"].Should().Equal("test test");
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
