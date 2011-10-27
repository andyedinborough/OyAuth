using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace SimpleAuth {

    public class Link : IComparable<Link> {
        private static Regex rxRootDomain = new Regex(@"^.*?([a-z0-9-]{2,}\.[a-z]{2,4}(\.[a-z]{2}){0,1})$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static string GetRootDomain(string host) {
            host = rxRootDomain.Match(host).Groups[1].Value;
            if (host.StartsWith("www.")) return host.Substring(4);
            else return host;
        }

        public Uri Uri { get; set; }
        public string Url { get; set; }
        public string NormalizedUrlQuery { get; set; }
        public string NormalizedUrl { get; set; }
        public int ID { get; set; }
        public string Host { get; set; }

        public override string ToString() {
            return NormalizedUrlQuery;
        }

        public Link(string url) {
            Url = url;
            Normalize();
        }

        public Link(Uri uri) {
            Uri = uri;
            Url = uri.OriginalString;
            Normalize();
        }

        public static int GetUrlID(string link) {
            return new Link(link).ID;
        }

        public static string Normalize(string url, bool stripQuery = false) {
            var link = new Link(url);
            return stripQuery ? link.NormalizedUrl : link.NormalizedUrlQuery;
        }

        public static string NormalizeHost(string host) {
            if (host == null) return string.Empty;
            if (host.Contains("://")) host = host.Substring(host.IndexOf("://") + 3);
            if (host.Contains("/")) host = host.Substring(0, host.IndexOf("/"));

            return (host.StartsWith("www.") ? host.Substring(4) : host).ToLower();
        }

        private string NormalizeQueryValue(string value) {
            value = value ?? string.Empty;
            if (value.Contains('%')) {
                try {
                    value = Uri.UnescapeDataString(value);
                } catch { }
            }
            value = Uri.EscapeDataString(value);
            return value;
        }

        private void Normalize() {
            if (Url.IsNullOrEmpty()) return;
            Url = Url.ToLower();
            if (!Url.StartsWith("http")) Url = "http://" + Url;

            if (Uri == null) Uri = Url.ToUri();
            if (Uri == null) return;

            string domain = NormalizeHost(Uri.Host);
            string path = Uri.AbsolutePath;

            string query = Uri.Query.TrimStart('?');
            if (query.Length > 0) {
                var coll = Utilities.ParseQueryString(string.Empty, query);
                query = string.Empty;
                foreach (string name in coll.Keys.Select(x => x.NotNull().ToLower()).OrderBy(x => x))
                    query = string.Concat(query, query.Length == 0 ? '?' : '&', name, "=", NormalizeQueryValue(coll[name]));
            }

            string file = path.EndsWith("/") ? string.Empty : path.Substring(path.LastIndexOf("/") + 1);
            if (file.Length > 0 && !file.Contains("."))
                path += "/";
            else if (file.StartsWith("default.") || file.StartsWith("index."))
                path = path.Substring(0, path.LastIndexOf("/") + 1);

            NormalizedUrlQuery = string.Concat(domain, path, query);
            NormalizedUrl = string.Concat(domain, path);
            ID = NormalizedUrl.GetHashCode();
            Host = domain;
        }

        public int CompareTo(Link other) {
            return string.Compare(NormalizedUrlQuery, other == null ? null : other.NormalizedUrlQuery);
        }
    }

}