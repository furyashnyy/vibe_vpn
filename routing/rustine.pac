// Rustine browser PAC: .ru/.su/.рф and local services bypass the proxy.
// This is a browser-level rule, not system-wide and not IP geolocation.
function FindProxyForURL(url, host) {
    var h = host.toLowerCase().replace(/\.$/, "");
    if (isPlainHostName(h) || h === "localhost" || dnsDomainIs(h, ".localhost") ||
        h === "127.0.0.1" || h === "::1") return "DIRECT";
    if (h === "ru" || dnsDomainIs(h, ".ru") ||
        h === "su" || dnsDomainIs(h, ".su") ||
        h === "xn--p1ai" || dnsDomainIs(h, ".xn--p1ai")) return "DIRECT";
    // PAC is not an IP geolocation DB; conservative RFC1918 IPv4 bypass.
    if (/^10\./.test(h) || /^192\.168\./.test(h) ||
        /^172\.(1[6-9]|2[0-9]|3[01])\./.test(h) || /^169\.254\./.test(h)) return "DIRECT";
    return "SOCKS5 127.0.0.1:1080";
}
