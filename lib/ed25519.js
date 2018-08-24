var nacl = require('tweetnacl');
var ed25519Utils = require('./ed25519Utils')

exports.Sign = function (message, privateKey) {
  return Buffer.from(nacl.sign.detached(message, privateKey))
}

exports.Verify = function (message, signature, publicKey) {
  return nacl.sign.detached.verify(message, signature, publicKey)
}
