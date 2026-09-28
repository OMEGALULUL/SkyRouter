// mongosh script: make genieacs-cwmp demand one username and secret from every
// router, by writing the cwmp.auth config expression. Safe to run again; a new
// secret replaces the old one.
//
// Without cwmp.auth GenieACS accepts any client that reaches port 7547, so this
// runs before any router is pointed at the ACS (README step 6):
//   mongosh "mongodb://127.0.0.1:27017/admin" --username admin \
//       --file deploy/genieacs/mongo/set-cwmp-auth.js --password
//
// Everything comes from the environment, so the secret never appears in the
// process list or in shell history:
//   CPE_USER     required; the ACS username routers are given, e.g. skybre-cpe
//   CPE_SECRET   required; hex, 32-128 characters (openssl rand -hex 24)
//   ACS_DB_NAME  optional; default "genieacs"
//
// The NBI has no endpoint for config documents, hence a database script. Once
// the cache hash is gone every GenieACS process reloads its config within about
// 5 seconds, so no restart is needed.
//
// SkyRouter's own script, not part of GenieACS.
(function () {
  "use strict";

  const env = process.env;

  function fail(message) {
    print("set-cwmp-auth.js: " + message);
    quit(2);
    // quit() ends mongosh; the throw only matters if it ever returns.
    throw new Error(message);
  }

  const dbName = env.ACS_DB_NAME || "genieacs";
  const user = env.CPE_USER || "";
  const secret = env.CPE_SECRET || "";

  if (!/^[A-Za-z0-9_-]{1,38}$/.test(dbName)) fail("ACS_DB_NAME must be 1-38 characters of [A-Za-z0-9_-]");
  // Both values are spliced into a GenieACS expression inside double quotes. The
  // character sets rule out a quote or backslash that would end the string early
  // and let the rest be read as expression syntax.
  if (!/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$/.test(user)) {
    fail("CPE_USER must be set to 1-64 characters of [A-Za-z0-9_.@-], starting with a letter or digit");
  }
  if (!/^[0-9A-Fa-f]{32,128}$/.test(secret)) {
    fail("CPE_SECRET must be set to 32-128 hex characters (openssl rand -hex 24)");
  }

  const target = db.getSiblingDB(dbName);
  const expression = 'AUTH("' + user + '", "' + secret + '")';
  const written = target
    .getCollection("config")
    .updateOne({ _id: "cwmp.auth" }, { $set: { value: expression } }, { upsert: true });
  if (!written || written.acknowledged !== true) fail("MongoDB did not acknowledge the cwmp.auth write");

  // GenieACS only re-reads config when this hash changes or expires (after up to
  // 300 seconds). Deleting it makes the change apply at the next 5-second check.
  target.getCollection("cache").deleteOne({ _id: "cwmp-local-cache-hash" });

  print("set-cwmp-auth.js: routers must now log in to the ACS as " + user + " (the secret is not shown)");
})();
