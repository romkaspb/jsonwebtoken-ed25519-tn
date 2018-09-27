var nacl = require('tweetnacl');

exports.Sign = function (message, privateKey) {
  return Buffer.from(nacl.sign.detached(message, privateKey))
}

exports.Verify = function (message, signature, publicKey) {
  return nacl.sign.detached.verify(message, signature, publicKey)
}

exports.ToPublic = function(privateKey) {
  return nacl.sign.keyPair.fromSecretKey(privateKey).publicKey
}
