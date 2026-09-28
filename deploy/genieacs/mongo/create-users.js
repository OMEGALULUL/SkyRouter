// mongosh script: create (or re-key) the MongoDB account GenieACS connects as,
// and the device indexes SkyRouter's queries rely on. Safe to run again.
//
// Run as a MongoDB user that can manage users (README step 4):
//   mongosh "mongodb://127.0.0.1:27017/admin" --username admin \
//       --file deploy/genieacs/mongo/create-users.js --password
//
// Everything comes from the environment, so the password never appears in the
// process list or in shell history:
//   ACS_DB_PASSWORD  required; hex, 32-128 characters (openssl rand -hex 24)
//   ACS_DB_NAME      optional; default "genieacs" (the e2e tests use "genieacs_e2e")
//   ACS_DB_USER      optional; default "genieacs"
//
// SkyRouter's own script, not part of GenieACS.
(function () {
  "use strict";

  const env = process.env;

  function fail(message) {
    print("create-users.js: " + message);
    quit(2);
    // quit() ends mongosh; the throw only matters if it ever returns.
    throw new Error(message);
  }

  const dbName = env.ACS_DB_NAME || "genieacs";
  const user = env.ACS_DB_USER || "genieacs";
  const password = env.ACS_DB_PASSWORD || "";

  if (!/^[A-Za-z0-9_-]{1,38}$/.test(dbName)) fail("ACS_DB_NAME must be 1-38 characters of [A-Za-z0-9_-]");
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(user)) fail("ACS_DB_USER must be 1-32 characters of [a-z0-9_-]");
  // Hex needs no percent-escaping inside GENIEACS_MONGODB_CONNECTION_URL and no
  // SASLprep normalisation, which the bundled driver treats as optional.
  if (!/^[0-9A-Fa-f]{32,128}$/.test(password)) {
    fail("ACS_DB_PASSWORD must be set to 32-128 hex characters (openssl rand -hex 24)");
  }

  const target = db.getSiblingDB(dbName);
  // readWrite covers everything genieacs-cwmp and genieacs-nbi do, including the
  // TTL indexes they create at start-up, and nothing outside their own database.
  const roles = [{ role: "readWrite", db: dbName }];
  const mechanisms = ["SCRAM-SHA-256"];

  if (target.getUser(user)) {
    target.updateUser(user, { pwd: password, roles: roles, mechanisms: mechanisms });
    print("create-users.js: updated the password and roles of " + user + " on " + dbName);
  } else {
    target.createUser({ user: user, pwd: password, roles: roles, mechanisms: mechanisms });
    print("create-users.js: created " + user + " with readWrite on " + dbName);
  }

  // SkyRouter lists devices newest check-in first, filters by tag and looks up
  // serial numbers. Without these every dashboard poll scans the collection.
  // createIndex is a no-op when an identical index exists.
  const devices = target.getCollection("devices");
  devices.createIndex({ _lastInform: -1 });
  devices.createIndex({ _tags: 1 });
  devices.createIndex({ "_deviceId._SerialNumber": 1 });
  print("create-users.js: device indexes are in place on " + dbName + ".devices");
})();
