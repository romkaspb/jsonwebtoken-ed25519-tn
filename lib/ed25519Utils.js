var PRIVATE_KEY_SIZE = 64;
var PUBLIC_KEY_SIZE = 32;
var SIGNATURE_SIZE = 64;

var isModern = (typeof Buffer.from === 'function');

function bufferFromString(string, format) {
  if (isModern) {
    return Buffer.from(string, format || 'utf8');
  } else {
    return new Buffer(string, format || 'utf8');
  }
}

function toBuffer(stringOrBuffer, expectedSize) { // accepts a buffer, hex-string or base64-string
  var result;
  if (Buffer.isBuffer(stringOrBuffer)) {
    result = stringOrBuffer;
  } else if (typeof stringOrBuffer === 'string') {
    // Parsing of hex-strings stops immediately at the non-hex character, so hex-strings must be exactly expectedSize * 2 chars long
    // Base64 strings may have spaces, for example, which will be ignored.
    result = bufferFromString(stringOrBuffer, ((stringOrBuffer.length === (expectedSize * 2)) ? 'hex' : 'base64'));
    if (result.length !== expectedSize) {
      throw new Error('Invalid input length or format');
    }
  } else {
    throw new Error('Invalid input type');
  }
  if (result.length !== expectedSize) {
    throw new Error('Unexpected size');
  }
  return result;
}

exports.toPrivateKey = function(stringOrBuffer) {
  return toBuffer(stringOrBuffer, PRIVATE_KEY_SIZE);
};

exports.toPublicKey = function(stringOrBuffer) {
  return toBuffer(stringOrBuffer, PUBLIC_KEY_SIZE);
};

exports.bufferFromString = bufferFromString;
exports.PRIVATE_KEY_SIZE = PRIVATE_KEY_SIZE;
exports.PUBLIC_KEY_SIZE = PUBLIC_KEY_SIZE;
exports.SIGNATURE_SIZE = SIGNATURE_SIZE;
