var ed25519 = require('./ed25519');
var ed25519Utils = require('./ed25519Utils')
var base64url = require('./base64url');

module.exports = function (privateKey) {
  privateKey = ed25519Utils.toPrivateKey(privateKey);
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64url(ed25519.ToPublic(privateKey))
  };
}
