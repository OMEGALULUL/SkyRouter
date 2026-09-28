// skybre-inform: a SkyRouter provision, written for the documented GenieACS 1.2
// provision API (declare, clear, ext). It contains no GenieACS code. Its preset runs
// it in every session, with args [<periodic inform interval in seconds>].
//
// It owns ManagementServer.* and nothing else. It makes the router check in on a
// fixed interval, and it sets the credentials GenieACS uses for connection
// requests: the device ID as the username, and a password from SkyRouter's
// extension, an HMAC of the device ID under a secret that never leaves this
// host. A value derived from the device ID alone could be recomputed by anyone
// who can read the router's label.
//
// Every check is gated on a per-device daily timestamp, so on most sessions this
// costs no RPCs at all. Both roots are declared because the router has only one.
// These declarations carry no path timestamp, so GenieACS looks for the missing
// root once and not again.

// Kept in step with MIN_INFORM_INTERVAL and MAX_INFORM_INTERVAL in bootstrap.py,
// which validates the argument before the preset is installed.
const MIN_INTERVAL = 60;
const MAX_INTERVAL = 86400;

const interval = args[0];
if (typeof interval !== "number" || !Number.isInteger(interval) || interval < MIN_INTERVAL || interval > MAX_INTERVAL) {
  // Fail on this channel, which SkyRouter's health check reports. Falling back to
  // a default would hide that the preset was changed by hand.
  throw new Error("skybre-inform needs an inform interval of " + MIN_INTERVAL + "-" + MAX_INTERVAL + " seconds");
}

// Date.now(period) is the start of the current period, shifted by an offset
// derived from the device ID. Each router therefore gets its own daily boundary,
// and the fleet does not re-check at the same moment.
const daily = Date.now(86400000);
// A fixed time of day for each router, so a fleet's informs spread across the
// interval instead of arriving together. It is a date on 1970-01-01. TR-069
// treats PeriodicInformTime as a reference point for the schedule, not as the
// time the schedule starts.
const informPhase = daily % 86400000;

// Read before anything else is declared. DeviceID.* is always cached, so this
// needs no RPC and does not force the declarations below into a separate round.
const deviceId = declare("DeviceID.ID", {value: 1}).value[0];

const crPassword = ext("skyrouter", "crPassword", deviceId);
if (typeof crPassword !== "string" || !/^[0-9a-f]{16,64}$/.test(crPassword)) {
  // Without this check, a broken extension would set the password to "undefined".
  // The value is left out of the message because faults are readable through the NBI.
  throw new Error("the skyrouter extension returned no usable connection-request password");
}

for (const root of ["InternetGatewayDevice", "Device"]) {
  const server = root + ".ManagementServer.";
  declare(server + "PeriodicInformEnable", {value: daily}, {value: true});
  declare(server + "PeriodicInformInterval", {value: daily}, {value: interval});
  declare(server + "PeriodicInformTime", {value: daily}, {value: informPhase});
  declare(server + "ConnectionRequestUsername", {value: daily}, {value: deviceId});
  // The password is write-only and always reads back as "". {value: 1} fetches it
  // once, so GenieACS has a cached value to compare against, and never again.
  // After a successful write GenieACS caches the value it sent, so the password
  // is not re-sent every day. After a factory reset, skybre-bootstrap's clear()
  // is what gets it sent again.
  declare(server + "ConnectionRequestPassword", {value: 1}, {value: crPassword});
}
