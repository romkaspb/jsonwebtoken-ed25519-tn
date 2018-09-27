var ed25519 = require('./ed25519');
var ed25519Utils = require('./ed25519Utils')
var base64url = require('./base64url');

var isModern = (typeof Buffer.from === 'function');

function toBuffer(array) {
  if (isModern) {
    return Buffer.from(array);
  } else {
    return new Buffer(array);
  }
}

module.exports = function (privateKey) {
  privateKey = ed25519Utils.toPrivateKey(privateKey);
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64url(toBuffer(ed25519.ToPublic(privateKey)))
  };
}
