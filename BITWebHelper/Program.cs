using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Text.Json.Nodes;
using System.CommandLine;
using System.CommandLine.Parsing;

namespace BITWebHelper {

    static class XEncode {

        public static uint[] CompressBytes(byte[] raw, bool addlen) {
            int len = raw.Length;
            uint[] vec = new uint[((len + 3) >> 2) + (addlen ? 1 : 0)];
            Buffer.BlockCopy(raw, 0, vec, 0, len);
            if (addlen) {
                vec[((len + 3) >> 2)] = (uint)len;
            }
            return vec;
        }

        public static byte[] DecompressBytes(uint[] vec, bool addlen) {
            int len = vec.Length, rawlen = (len - (addlen ? 1 : 0)) << 2;
            if (addlen) {
                int m = (int)vec[len - 1];
                if ((m < rawlen - 3) || (m > rawlen))
                    throw new Exception("Bad inputs for XEncode.DecompressBytes!");
                rawlen = m;
            }
            byte[] raw = new byte[rawlen];
            Buffer.BlockCopy(vec, 0, raw, 0, rawlen);
            return raw;
        }

        public static byte[] Encode(string data, string key) {
            return Encode(Encoding.ASCII.GetBytes(data), Encoding.ASCII.GetBytes(key));
        }

        public static byte[] Encode(byte[] str, byte[] key) {
            uint[] v = CompressBytes(str, true);
            uint n = (uint)v.Length - 1;
            if (n < 1) {
                throw new Exception("Bad inputs for XEncode.Encode!");
            }
            uint[] k = CompressBytes(key, false);
            if (k.Length < 4) {
                uint[] kk = new uint[4];
                k.CopyTo(kk, 0);
                k = kk;
            }
            uint z = v[n],
                    y, m, e,
                    c = unchecked((uint)-1640531527),
                    q = 6 + 52 / (n + 1),
                    d = 0;
            while (0 < q--) {
                d += c;
                e = (d >> 2) & 3;
                for (int i = 0; i < n; i++) {
                    y = v[i + 1];
                    m = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4) ^ d ^ y) + (k[(i & 3) ^ e] ^ z);
                    z = v[i] = v[i] + m;
                }
                y = v[0];
                m = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4) ^ d ^ y) + (k[(n & 3) ^ e] ^ z);
                z = v[n] = v[n] + m;
            }
            return DecompressBytes(v, false);
        }

    }

    static class WebHelper {

        private static readonly string BASE_URL = "http://10.0.0.55/cgi-bin/srun_portal";
        private static readonly string CHALLENGE_URL = "http://10.0.0.55/cgi-bin/get_challenge";
        private static readonly string CHECK_URL = "http://10.0.0.55/cgi-bin/rad_user_info";

        private static readonly string RAW_B64_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly string TRANS_B64_STR = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

        private static string client_ip = "";
        private static string challenge = "";

        private static string Base64ModEncode(byte[] data) {
            string base64 = Convert.ToBase64String(data);
            string modstr = "";
            for (int i = 0; i < base64.Length; ++i) {
                if (RAW_B64_STR.IndexOf(base64[i]) != -1) {
                    modstr += TRANS_B64_STR[RAW_B64_STR.IndexOf(base64[i])];
                }
                else {
                    modstr += base64[i];
                }
            }
            return modstr;
        }

        private static string ByteToHex(byte[] data) {
            string hex = "";
            for (int i = 0; i < data.Length; ++i) {
                hex += data[i].ToString("x2");
            }
            return hex;
        }

        private static string HexHMACMD5(string data, string key) {
            HMACMD5 provider = new(Encoding.UTF8.GetBytes(key));
            byte[] hash = provider.ComputeHash(Encoding.UTF8.GetBytes(data));
            provider.Dispose();
            return ByteToHex(hash);
        }

        private static string HexSHA1(string data) {
            SHA1 provider = SHA1.Create();
            byte[] hash = provider.ComputeHash(Encoding.ASCII.GetBytes(data));
            provider.Dispose();
            return ByteToHex(hash);
        }

        private static string GetTimeStamp() {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalMilliseconds).ToString();
        }

        private static string GetChallengeReqStr(string username) {
            string callbackstr = "jQuery" + GetTimeStamp(),
                    usernamestr = HttpUtility.UrlEncode(username);
            string ChallengeReqStr = string.Format("callback={0}&username={1}", callbackstr, usernamestr);
            return ChallengeReqStr;
        }

        private static string GetCheckReqStr() {
            string callbackstr = "jQuery" + GetTimeStamp();
            string CheckReqStr = string.Format("callback={0}", callbackstr);
            return CheckReqStr;
        }

        private static string GetLogoutReqStr(string username) {
            string callbackstr = "jQuery" + GetTimeStamp(),
                    actionstr = "logout",
                    usernamestr = HttpUtility.UrlEncode(username);
            string LogoutReqStr = string.Format("callback={0}&action={1}&username={2}", callbackstr, actionstr, usernamestr);
            return LogoutReqStr;
        }

        private static string GetLoginReqStr(string ac_id, string username, string password) {
            string callbackstr = "jQuery" + GetTimeStamp(),
                   actionstr = "login",
                   nstr = "200",
                   typestr = "1",
                   ipstr = client_ip,
                   usernamestr = HttpUtility.UrlEncode(username),
                   hmd5 = HexHMACMD5(/*USER_PASSWORD*/ "", challenge),
                   passwordstr = HttpUtility.UrlEncode("{MD5}" + hmd5);
            string infojson = string.Format("{{\"username\":\"{0}\",\"password\":\"{1}\",\"ip\":\"{2}\",\"acid\":\"{3}\",\"enc_ver\":\"srun_bx1\"}}", username, password, client_ip, ac_id);
            string info = "{SRBX1}" + Base64ModEncode(XEncode.Encode(infojson, challenge)),
                   infostr = HttpUtility.UrlEncode(info);
            string checksumstr = HexSHA1(challenge + username + challenge + hmd5 + challenge + ac_id + challenge + ipstr + challenge + nstr + challenge + typestr + challenge + info);
            string LoginReqStr = string.Format("callback={0}&action={1}&n={2}&type={3}&ac_id={4}&ip={5}&username={6}&password={7}&info={8}&chksum={9}", callbackstr, actionstr, nstr, typestr, ac_id, ipstr, usernamestr, passwordstr, infostr, checksumstr);
            return LoginReqStr;
        }

        private static async Task<JsonNode?> SendReqAsync(string url, string reqstr) {
            string target = url + "?" + reqstr;
            Console.WriteLine("Request: {0}", target);
            string response = "";
            using (HttpClient client = new()) {
                try {
                    response = await client.GetStringAsync(target);
                }
                catch (HttpRequestException e) {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message: {0}", e.Message);
                    return null;
                }
            }
            Console.WriteLine("Response: {0}", response);
            response = response[20..^1];
            JsonNode? jsonobj = JsonNode.Parse(response);
            return jsonobj;
        }

        private static bool CheckResponse(JsonNode? jsonobj) {
            if (jsonobj == null) {
                return false;
            }
            string? res = (string?)jsonobj["res"];
            if (res == null) {
                return false;
            }
            if (res != "ok") {
                string? error = (string?)jsonobj["error"];
                string? error_msg = (string?)jsonobj["error_msg"];
                Console.WriteLine("An error occurred: {0}, {1}, {2}", res, error, error_msg);
                return false;
            }
            return true;
        }

        private static void RefreshChallenge(string username) {
            JsonNode? retjson = SendReqAsync(CHALLENGE_URL, GetChallengeReqStr(username)).GetAwaiter().GetResult();
            if (CheckResponse(retjson)) {
                string? _client_ip = (string?)retjson?["client_ip"];
                if (_client_ip == null) {
                    throw new Exception("Bad JSON for parsing!");
                }
                string? _challenge = (string?)retjson?["challenge"];
                if (_challenge == null) {
                    throw new Exception("Bad JSON for parsing!");
                }
                client_ip = _client_ip;
                challenge = _challenge;
                Console.WriteLine("Get-Challenge succeeded.");
                Console.WriteLine("IP: {0}", client_ip);
                Console.WriteLine("Challenge: {0}", challenge);
            }
            else {
                Console.WriteLine("Get-Challenge failed.");
            }
        }

        public static int Login(string ac_id, string username, string password) {
            Console.WriteLine("\n\nTIME: {0}", DateTime.Now.ToString());

            RefreshChallenge(username);
            JsonNode? retjson = SendReqAsync(BASE_URL, GetLoginReqStr(ac_id, username, password)).GetAwaiter().GetResult();
            if (CheckResponse(retjson)) {
                Console.WriteLine("Login succeeded.");
                return 0;
            }
            else {
                Console.WriteLine("Login failed.");
                return 1;
            }
        }

        public static int Logout(string username) {
            Console.WriteLine("\n\nTIME: {0}", DateTime.Now.ToString());

            RefreshChallenge(username);
            JsonNode? retjson = SendReqAsync(BASE_URL, GetLogoutReqStr(username)).GetAwaiter().GetResult();
            if (CheckResponse(retjson)) {
                Console.WriteLine("Logout succeeded.");
                return 0;
            }
            else {
                Console.WriteLine("Logout failed.");
                return 1;
            }
        }

        public static int Check() {
            Console.WriteLine("\n\nTIME: {0}", DateTime.Now.ToString());

            JsonNode? retjson = SendReqAsync(CHECK_URL, GetCheckReqStr()).GetAwaiter().GetResult();
            if (retjson != null) {
                string? error = (string?)retjson["error"];
                if (error == "ok") {
                    Console.WriteLine("You're currently online.");
                    return 0;
                }
                else if (error == "not_online_error") {
                    Console.WriteLine("You're not online.");
                    return 1;
                }
                Console.WriteLine("Failed to check online status.");
                return 1;
            }
            else {
                Console.WriteLine("Failed to check online status.");
                return 1;
            }
        }
    }

    class Program {
        static int Main(string[] args) {
            var rootCommand = new RootCommand("BITWebHelper");

            var checkCommand = new Command(
                name: "check",
                description: "Check whether you have logged in, return 0 if logged in, 1 if not.");
            rootCommand.AddCommand(checkCommand);

            var loginCommand = new Command(
                name: "login",
                description: "Log in.");
            rootCommand.AddCommand(loginCommand);

            var logoutCommand = new Command(
                name: "logout",
                description: "Log out.");
            rootCommand.AddCommand(logoutCommand);


            var acidArg = new Argument<string>(
                name: "ac_id",
                description: "Usually 1 or 8, you can check this out by directly visiting " +
                             "http://10.0.0.55 and looking for \"ac_id\" in the link after redirection.");
            var usernameArg = new Argument<string>(
                name: "username",
                description: "Your username.");
            var passwordArg = new Argument<string>(
                name: "password",
                description: "Your password.");

            loginCommand.AddArgument(acidArg);
            loginCommand.AddArgument(usernameArg);
            loginCommand.AddArgument(passwordArg);

            logoutCommand.AddArgument(acidArg);
            logoutCommand.AddArgument(usernameArg);

            checkCommand.SetHandler(() => Task.FromResult(WebHelper.Check()));

            loginCommand.SetHandler(
                (ac_id, username, password) => Task.FromResult(WebHelper.Login(ac_id, username, password)), 
                acidArg, usernameArg, passwordArg);

            logoutCommand.SetHandler(
                (username) => Task.FromResult(WebHelper.Logout(username)), 
                usernameArg);

            return rootCommand.Invoke(args);
        }
    }
}
