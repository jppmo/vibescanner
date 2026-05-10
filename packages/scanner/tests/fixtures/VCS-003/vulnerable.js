const jwt = require('jsonwebtoken')

// Hardcoded known-bad secret, no expiry
function generateToken(userId) {
  return jwt.sign({ userId }, 'secret')
}

// Good secret but no expiry
function generateAdminToken(adminId) {
  return jwt.sign({ adminId, role: 'admin' }, process.env.JWT_SECRET)
}
