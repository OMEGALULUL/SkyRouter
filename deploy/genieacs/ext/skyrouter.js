// SkyRouter's GenieACS extension, installed as /opt/genieacs/ext/skyrouter.js.
//
// genieacs-cwmp loads this file in a long-lived child process and calls its
// exports as fn(args, callback), with every argument already turned into a
// string. The skybre-inform provision calls it as
//   ext("skyrouter", "crPassword", <device id>)
//
// SkyRouter's own code, not part of GenieACS. It uses only Node's standard library.
"use strict";

const crypto = require("crypto");

// Exactly what GenieACS generates as a device ID: OUI, optional ProductClass and
// Serial, joined by "-", with every character outside [A-Za-z0-9_] written as
// uppercase %XX. Anything else means the provision passed the wrong value, and
// a password derived from it would never match what the router was given.
const DEVICE_ID = /^(?:[A-Za-z0-9_]|%[0-9A-F]{2})+(?:-(?:[A-Za-z0-9_]|%[0-9A-F]{2})+){1,2}$/;
const MAX_DEVICE_ID_LENGTH = 256;

// Hex only, and at least 128 bits. A typo or an unfilled template placeholder
// then fails closed instead of quietly becoming a weak key.
const SECRET = /^[0-9A-Fa-f]{32,}$/;

// 32 hex characters is 128 bits, too many to guess, and short in case a router's
// firmware limits the field more tightly than the data model's 256 characters.
const PASSWORD_LENGTH = 32;

function refuse(callback, message) {
  // A plain Error, so GenieACS records the channel fault as "ext.Error", the code
  // SkyRouter's health check looks for. The message never includes the secret or
  // the arguments: faults are readable by anything that can reach the NBI.
  callback(new Error(message));
}

// crPassword(deviceId) = HMAC-SHA256(key = SKYROUTER_CR_SECRET, message = deviceId),
// both taken as UTF-8 bytes, lowercase hex, first 32 characters. In Python:
//   hmac.new(secret.encode(), device_id.encode(), hashlib.sha256).hexdigest()[:32]
// The secret is read on every call, so an unset secret refuses every call rather
// than only those made after some cached state went stale.
function crPassword(args, callback) {
  const secret = process.env.SKYROUTER_CR_SECRET;
  if (typeof secret !== "string" || !SECRET.test(secret)) {
    refuse(callback, "SKYROUTER_CR_SECRET is unset or shorter than 32 hex characters");
    return;
  }
  const deviceId = Array.isArray(args) && args.length === 1 ? args[0] : undefined;
  if (typeof deviceId !== "string" || deviceId.length > MAX_DEVICE_ID_LENGTH || !DEVICE_ID.test(deviceId)) {
    refuse(callback, "crPassword needs a GenieACS device ID as its only argument");
    return;
  }
  const digest = crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(deviceId, "utf8").digest("hex");
  callback(null, digest.slice(0, PASSWORD_LENGTH));
}

exports.crPassword = crPassword;
