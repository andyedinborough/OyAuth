using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Web;

namespace SimpleAuth {
    public class OpenID {
        /// <summary>
        /// The data store used for keeping state between OpenID requests.
        /// </summary>
        public class Info {
            public Info(NameValueCollection query) {
                Identity = query["openid.claimed_id"];
                Parameters = query;
                NormalizedIdentity = Link.Normalize(Identity, false);
            }

            public string Identity { get; private set; }
            public string NormalizedIdentity { get; private set; }
            private NameValueCollection Parameters { get; set; }

            public string this[ParamterTypes parameter] {
                get {
                    return GetValue(".value." + parameter.ToString())
                        ?? GetValue(".sreg." + parameter.ToString());
                }
            }

            private string GetValue(string key) {
                return Parameters.AllKeys
                        .Where(x => x.EndsWith(key))
                        .Select(x => Parameters[x])
                        .FirstOrDefault(x => !x.IsNullOrEmpty());
            }

            public string Email {
                get { return this[ParamterTypes.email]; }
            }

            public string FullName {
                get { return this[ParamterTypes.fullname] ?? (this[ParamterTypes.firstname] + " " + this[ParamterTypes.lastname]).Trim(); }
            }
        }

        private static bool CheckAuthentication(NameValueCollection query) {
            var id = query["openid.claimed_id"].ToUri();
            var endpoint = query["openid.op_endpoint"].ToUri();

            //### get data required for check_authentication
            string mode = "check_authentication";
            string handle = query["openid.assoc_handle"];
            string signature = query["openid.sig"];
            string signed = query["openid.signed"];
            string extra = string.Empty;

            //### loop through fields required by "openid.signed" and retrieve that data
            if (!string.IsNullOrEmpty(signed)) {
                string[] exemptions = { "mode", "assoc_handle", "sig", "signed" };
                string[] fields = signed.Split(',');
                foreach (string field in fields) {
                    if (exemptions.Contains(field)) continue;
                    extra += string.Format("openid.{0}={1}&", field, OAuth.UrlEncode(query["openid." + field]));
                }
                extra = "&" + extra.Substring(0, extra.Length - 1);
            }

            //### combine all the data together to form the request
            string post = string.Format("openid.mode={0}&openid.assoc_handle={1}&openid.sig={2}&openid.signed={3}{4}",
                mode,
                OAuth.UrlEncode(handle),
                OAuth.UrlEncode(signature),
                OAuth.UrlEncode(signed),
                extra
            );

            //### get response
            string html;
            using (var web = new WebClient { ContentType = "application/x-www-form-urlencoded" }) {
                html = web.UploadString(endpoint, post);
            }

            return !html.IsNullOrEmpty() && html.Contains("is_valid:true");
        }

        [Flags]
        public enum ParamterTypes {
            email = 1,
            fullname = 2, phone = 4,
            country = 8, language = 16,
            firstname = 32, lastname = 64
        }

        /// <summary>
        /// Perform redirection to the OpenID provider based on the specified identity.
        /// </summary>
        /// <param name="identity">The identity or OpenID URL.</param>
        /// <param name="requiredParameters">The required parameters. Can be null or string.empty.</param>
        /// <param name="optionalParameters">The optional parameters. Can be null or string.empty.</param>
        public static string GetLoginUrl(Uri identity, Uri return_to = null, ParamterTypes? requiredParameters = null, ParamterTypes? optionalParameters = null, Uri realm = null) {
            var servers = GetIdentityServer(identity);
            foreach (var serverInfo in servers) {
                if (serverInfo == null || serverInfo.Server == null) return string.Empty;

                //TODO: Check to see if server is operational; if not, then continue

                var query = HttpUtility.ParseQueryString("");
                query["openid.ns"] = "http://specs.openid.net/auth/2.0";
                query["openid.mode"] = "checkid_setup";
                if (realm != null) query["openid.realm"] = realm.ToString();
                query["openid.claimed_id"] = "http://specs.openid.net/auth/2.0/identifier_select";
                query["openid.identity"] = "http://specs.openid.net/auth/2.0/identifier_select";

                query["openid.ui.ns"] = "http://specs.openid.net/extensions/ui/1.0";
                query["openid.ui.mode"] = "popup";
                query["openid.ui.icon"] = "true";

                if (return_to != null) query["openid.return_to"] = return_to.ToString();

                if (requiredParameters != null || optionalParameters != null) {
                    query["openid.ns.sreg"] = "http://openid.net/extensions/sreg/1.1";
                    query["openid.ns.ax"] = "http://openid.net/srv/ax/1.0";
                    if (requiredParameters != null) AddParameters(query, requiredParameters.Value, "required");
                    if (optionalParameters != null) AddParameters(query, requiredParameters.Value, "optional");
                }

                return serverInfo.Server.GetLeftPart(UriPartial.Path) + "?" + query.ToString();
            }

            return null;
        }

        private static void AddParameters(NameValueCollection query, ParamterTypes parameters, string type) {
            if (parameters.Contains(ParamterTypes.fullname)) parameters = parameters.SetFlag(ParamterTypes.firstname, true).SetFlag(ParamterTypes.lastname, true);
            query["openid.sreg." + type] = EnumToCommaDelimited(parameters);
            var paramsWSchema = GetValues(parameters).Select(x => Tuple.Create(x, GetShemaUri(x))).Where(x => !x.Item2.IsNullOrEmpty()).ToArray();

            if (paramsWSchema.IsNullOrEmpty()) return;
            query["openid.ax.mode"] = "fetch_request";
            for (var i = 0; i < paramsWSchema.Length; i++) {
                query["openid.ax.type." + paramsWSchema[i].Item1.ToString()] = paramsWSchema[i].Item2;
            }
            query["openid.ax." + type] = paramsWSchema.Select(x => x.Item1.ToString()).Join(",");
        }

        private static string GetShemaUri(ParamterTypes type) {
            switch (type) {
                case ParamterTypes.email: return "http://axschema.org/contact/email";
                case ParamterTypes.country: return "http://axschema.org/contact/country/home";
                case ParamterTypes.language: return "http://axschema.org/contact/pref/language";
                case ParamterTypes.firstname: return "http://axschema.org/namePerson/first";
                case ParamterTypes.lastname: return "http://axschema.org/namePerson/last";
                case ParamterTypes.fullname: return "http://axschema.org/namePerson";
                default: return null;
            }
        }

        private static string EnumToCommaDelimited(Enum e) {
            return e == null ? null : e.ToString().Replace(", ", ",");
        }

        private static IEnumerable<T> GetValues<T>(T e) where T : struct,IConvertible {
            return System.Enum.GetValues(typeof(T)).Cast<T>().Where(x => e.Contains(x));
        }

        /// <summary>
        /// Authenticates the request from the OpenID provider.
        /// </summary>
        public static Info Authenticate(NameValueCollection querystring) {
            if (!IsOpenIdRequest(querystring)) return null;

            var query = querystring ?? HttpContext.Current.Request.QueryString;
            if (!CheckAuthentication(query) || query["openid.mode"] != "id_res")
                return null;

            return new Info(query);
        }

        /// <summary>
        /// Gets a value indicating whether the request comes from an OpenID provider.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if this is an OpenID request; otherwise, <c>false</c>.
        /// </value>
        public static bool IsOpenIdRequest(NameValueCollection querystring) {
            return !querystring["openid.mode"].IsNullOrEmpty();
        }

        #region Private methods

        public class ServiceInfo {
            public Uri Server { get; set; }
            public Uri Delegate { get; set; }
        }

        /// <summary>
        /// Crawls the identity URL to find the auto-discovery link headers.
        /// </summary>
        public static IEnumerable<ServiceInfo> GetIdentityServer(Uri identity) {
            int n = 0;
            using (var client = new WebClient()) {
                client.Headers[HttpRequestHeader.Accept] = "application/xrds+xml";
                string html;
                Uri redirect = null;
                do {
                    html = client.DownloadString(redirect ?? identity).NotNull().Trim();
                    redirect = client.ResponseHeaders["X-XRDS-Location"].ToUri();
                } while (redirect != null && n < 10);

                var options = XHTMLr.XHTML.Options.Default;
                if (html.StartsWith("<?xml"))
                    options = options.Remove(XHTMLr.XHTML.Options.EnforceHtmlElement).SetFlag(XHTMLr.XHTML.Options.KeepTagCase, true);

                html = XHTMLr.XHTML.ToXml(html, options);
                var xdoc = System.Xml.Linq.XDocument.Parse(html);

                var links = xdoc.Descendants("link");
                if (links.Any()) {
                    var info = new ServiceInfo();
                    foreach (var link in xdoc.Descendants("link")) {
                        if ((string)link.Attribute("rel") == "openid.server")
                            info.Server = ((string)link.Attribute("href")).ToUri();
                        if ((string)link.Attribute("rel") == "openid.delegate")
                            info.Delegate = ((string)link.Attribute("href")).ToUri();
                    }
                    yield return info;

                } else {
                    var services = xdoc.Descendants("Service")
                        .Where(x => x.Elements("URI").Any() && x.Elements("Type").Any(e => e.Value.NotNull().Contains("openid.net")))
                        .OrderBy(x => ((string)x.Attribute("priority")).ToInt());
                    foreach (var service in services) {
                        yield return new ServiceInfo {
                            Server = ((string)service.Element("URI")).ToUri(),
                            Delegate = ((string)service.Element("Delegate")).ToUri()
                        };
                    }
                }
            }
        }

        #endregion
    }
}