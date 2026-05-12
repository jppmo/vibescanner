const crypto = require("crypto");

function hashPassword(pw) {
  return crypto.createHash("sha256").update(pw).digest("hex");
}

const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
