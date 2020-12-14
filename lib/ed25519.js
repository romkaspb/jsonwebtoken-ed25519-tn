var nacl = require('tweetnacl');

function bufferToUint8Array(buffer) {
  return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength / Uint8Array.BYTES_PER_ELEMENT);
}

exports.Sign = function (message, privateKey) {
  const msg = bufferToUint8Array((message))
  const privKey = bufferToUint8Array((privateKey))
  return Buffer.from(nacl.sign.detached(msg, privKey))
}

exports.Verify = function (message, signature, publicKey) {
  const msg = bufferToUint8Array((message))
  const sig = bufferToUint8Array((signature))
  const privKey = bufferToUint8Array((publicKey))
  return nacl.sign.detached.verify(msg, sig, privKey)
}

exports.ToPublic = function(privateKey) {
  const privKey = bufferToUint8Array((privateKey))
  return nacl.sign.keyPair.fromSecretKey(privKey).publicKey
}
