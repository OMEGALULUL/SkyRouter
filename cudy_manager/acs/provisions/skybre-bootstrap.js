// skybre-bootstrap: a SkyRouter provision, written for the documented GenieACS 1.2
// provision API (declare, clear, ext). It contains no GenieACS code. Its preset runs
// it only in a session that carries the "0 BOOTSTRAP" event.
//
// A router sends 0 BOOTSTRAP after a factory reset or when it is pointed at a new
// ACS. Everything GenieACS cached about it before that describes a configuration
// the router no longer has, including the connection-request credentials that
// skybre-inform set. GenieACS trusts its cache, so it would not re-apply them
// until the next daily check, and connection requests would fail until then.
// Clearing everything cached before this session makes this session's other
// provisions rediscover the router and re-apply what they own.
//
// Nothing cached in this session is older than its start, so what the router
// reported in this session's Inform survives the clear.
const sessionStart = Date.now();
clear("InternetGatewayDevice", sessionStart);
clear("Device", sessionStart);
