const crypto = require("crypto");

// MD5 — broken
function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// SHA-1 — deprecated
function fingerprint(data) {
  return crypto.createHash("sha1").update(data).digest("hex");
}

// DES cipher — broken
const cipher = crypto.createCipheriv("des-cbc", key, iv);

// RC4 — broken
const rc4 = crypto.createCipheriv("rc4", key, "");

// AES-ECB — pattern leakage
const ecb = crypto.createCipheriv("aes-256-ecb", key, "");
