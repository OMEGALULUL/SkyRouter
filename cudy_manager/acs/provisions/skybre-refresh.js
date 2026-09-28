// skybre-refresh: a SkyRouter provision, written for the documented GenieACS 1.2
// provision API (declare, clear, ext). It contains no GenieACS code. Its preset runs
// it in every session, with no arguments.
//
// SkyRouter's dashboard reads routers only from GenieACS's cache and never waits
// on a router. This script keeps fresh the parts the dashboard shows: device
// info, Wi-Fi, LAN hosts and WAN state. It runs at the end of every session,
// after any queued tasks, and that shapes it:
// * It only declares what to fetch, never a desired value. SkyRouter's tasks own
//   every Wi-Fi leaf, and a value declared here would undo a task that ran
//   earlier in the same session.
// * It never reads .value. SkyRouter reads values through the NBI, and each read
//   here would make GenieACS stop, fetch and re-run the script within its 50 ms
//   budget.
// * Write-only secrets are only discovered (does the leaf exist, is it
//   writable?), never fetched. A router that follows the spec returns "", so a
//   fetch gains nothing. A router that breaks the spec would copy the live
//   passphrase into GenieACS's database every hour.
//
// Timestamps come from Date.now(period). It shifts each router's boundaries by an
// offset derived from the device ID, so a fleet's refreshes spread across the
// hour.
const hourly = Date.now(3600000);
const daily = Date.now(86400000);

// Radios, SSIDs and WAN connections are rarely added or removed, so their
// instances are rediscovered daily and their values re-read hourly. LAN hosts
// and Wi-Fi stations come and go, so they are rediscovered hourly as well.
function stable(path) {
  declare(path, {path: daily, value: hourly});
}
function churning(path) {
  declare(path, {path: hourly, value: hourly});
}
function secret(path) {
  declare(path, {path: daily, writable: daily});
}
function exists(path) {
  declare(path, {path: daily});
}
function each(base, leaves, kind) {
  for (const leaf of leaves) kind(base + "." + leaf);
}

// Checking the roots before declaring anything else costs nothing once GenieACS
// knows which roots the router has. Declaring timed rediscovery under a root the
// router lacks might make GenieACS search for that root again on every period.
const hasIgd = Boolean(declare("InternetGatewayDevice", {path: 1}).size);
const hasDevice = Boolean(declare("Device", {path: 1}).size);

const DEVICE_INFO = ["Manufacturer", "ModelName", "SerialNumber", "HardwareVersion", "SoftwareVersion", "UpTime"];
// Where the band can be read from a radio object, in either data model.
const RADIO = [
  "Enable", "Status", "OperatingFrequencyBand", "SupportedFrequencyBands", "Channel", "PossibleChannels",
  "OperatingStandards", "SupportedStandards",
];
// A vendor leaf that is absent costs nothing: GenieACS lists an object's children
// before it fetches any of them.
const RSSI = ["X_HW_RSSI"];

if (hasIgd) {
  const igd = "InternetGatewayDevice";
  each(igd + ".DeviceInfo", DEVICE_INFO, stable);

  // TR-098 has no band parameter, so every leaf a band can be inferred from is
  // fetched: vendor band leaves, a hybrid radio reference, the channel, then the
  // standard.
  const wlan = igd + ".LANDevice.*.WLANConfiguration.*";
  each(wlan, [
    "SSID", "Enable", "Status", "RadioEnabled", "Channel", "PossibleChannels", "Standard",
    "X_HW_RFBand", "X_TP_Band", "X_HW_Standard", "LowerLayers",
    "BeaconType", "BasicEncryptionModes", "BasicAuthenticationMode",
    "WPAEncryptionModes", "WPAAuthenticationMode", "IEEE11iEncryptionModes", "IEEE11iAuthenticationMode",
    "TotalAssociations", "TotalPSKFailures",
  ], stable);
  // Where a passphrase may be written, depending on the vendor.
  each(wlan, ["PreSharedKey.1.KeyPassphrase", "KeyPassphrase", "X_TP_PreSharedKey"], secret);
  each(wlan + ".AssociatedDevice.*", [
    "AssociatedDeviceMACAddress", "AssociatedDeviceIPAddress", "AssociatedDeviceAuthenticationState", ...RSSI,
  ], churning);
  // Huawei's hybrid tree: TR-181-style radios under a TR-098 LANDevice, which
  // WLANConfiguration.LowerLayers points at.
  each(igd + ".LANDevice.*.WiFi.Radio.*", RADIO, stable);

  each(igd + ".LANDevice.*.Hosts.Host.*", [
    "MACAddress", "IPAddress", "HostName", "Active", "Layer2Interface", "InterfaceType", ...RSSI,
  ], churning);

  // DefaultConnectionService names the internet WAN. Where it is missing, ONTs
  // label their connections by name or in a vendor service leaf.
  stable(igd + ".Layer3Forwarding.DefaultConnectionService");
  for (const kind of ["WANIPConnection", "WANPPPConnection"]) {
    each(igd + ".WANDevice.*.WANConnectionDevice.*." + kind + ".*", [
      "ExternalIPAddress", "ConnectionStatus", "Uptime", "Name",
      "X_HW_SERVICELIST", "X_ZTE-COM_ServiceList", "X_CT-COM_ServiceList", "X_TP_ServiceType",
    ], stable);
  }
}

if (hasDevice) {
  each("Device.DeviceInfo", DEVICE_INFO, stable);
  // Tell TR-181 Issue 2 (2.x) apart from Issue 1, which has Device.LAN and no
  // Device.WiFi, and so gets no Wi-Fi writes.
  stable("Device.RootDataModelVersion");
  stable("Device.DeviceSummary");
  exists("Device.LAN");

  // The band is found by following references: AccessPoint.SSIDReference, then
  // SSID.LowerLayers, then Radio.OperatingFrequencyBand. All three are fetched.
  each("Device.WiFi.Radio.*", RADIO, stable);
  each("Device.WiFi.SSID.*", ["Enable", "Status", "SSID", "LowerLayers"], stable);
  const ap = "Device.WiFi.AccessPoint.*";
  each(ap, [
    "Enable", "Status", "SSIDReference", "AssociatedDeviceNumberOfEntries", "Security.ModeEnabled",
    "Security.ModesSupported",
  ], stable);
  each(ap, ["Security.KeyPassphrase", "Security.SAEPassphrase"], secret);
  each(ap + ".AssociatedDevice.*", ["MACAddress", "SignalStrength", "Active"], churning);
  // An SSID used by a Wi-Fi EndPoint is the router's uplink to another network,
  // not a network it serves.
  stable("Device.WiFi.EndPoint.*.SSIDReference");

  each("Device.Hosts.Host.*", [
    "PhysAddress", "IPAddress", "HostName", "Active", "Layer1Interface", "AssociatedDevice", "InterfaceType",
  ], churning);

  // TR-181 does not mark the internet WAN. It is found from the default route,
  // then from NAT, then from the first dynamically addressed interface.
  each("Device.IP.Interface.*", ["Enable", "Status", "Name", "LowerLayers", "LastChange", "Loopback"], stable);
  each("Device.IP.Interface.*.IPv4Address.*", ["Enable", "IPAddress", "AddressingType"], stable);
  each("Device.PPP.Interface.*", ["ConnectionStatus", "LastChange", "IPCP.LocalIPAddress"], stable);
  each("Device.Routing.Router.*.IPv4Forwarding.*", ["Enable", "DestIPAddress", "DestSubnetMask", "Interface"], stable);
  each("Device.NAT.InterfaceSetting.*", ["Enable", "Interface"], stable);
}
