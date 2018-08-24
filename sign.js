var timespan = require('./lib/timespan');
var ed25519Utils = require('./lib/ed25519Utils');
var util = require('util');
var ed25519 = require('tweetnacl');
var jws = require('jws');
var includes = require('lodash.includes');
var isBoolean = require('lodash.isboolean');
var isInteger = require('lodash.isinteger');
var isNumber = require('lodash.isnumber');
var isPlainObject = require('lodash.isplainobject');
var isString = require('lodash.isstring');
var once = require('lodash.once');

var sign_options_schema = {
  expiresIn: { isValid: function(value) { return isInteger(value) || isString(value); }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
  notBefore: { isValid: function(value) { return isInteger(value) || isString(value); }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
  audience: { isValid: function(value) { return isString(value) || Array.isArray(value); }, message: '"audience" must be a string or array' },
  algorithm: { isValid: includes.bind(null, ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'Ed25519', 'none']), message: '"algorithm" must be a valid string enum value' },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  mutatePayload: { isValid: isBoolean, message: '"mutatePayload" must be a boolean' }
};

var registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
};

function validate(schema, allowUnknown, object, parameterName) {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.');
  }
  Object.keys(object)
    .forEach(function(key) {
      var validator = schema[key];
      if (!validator) {
        if (!allowUnknown) {
          throw new Error('"' + key + '" is not allowed in "' + parameterName + '"');
        }
        return;
      }
      if (!validator.isValid(object[key])) {
        throw new Error(validator.message);
      }
    });
}

function validateOptions(options) {
  return validate(sign_options_schema, false, options, 'options');
}

function validatePayload(payload) {
  return validate(registered_claims_schema, true, payload, 'payload');
}

var options_to_payload = {
  'audience': 'aud',
  'issuer': 'iss',
  'subject': 'sub',
  'jwtid': 'jti'
};

var options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid',
];

function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function fixEd25519Signature(noneToken, privateKey) {
  var splitted = noneToken.split('.', 2);
  var header = JSON.parse(ed25519Utils.bufferFromString(splitted[0], 'base64'));
  header.alg = 'Ed25519';
  var securedInput = util.format('%s.%s', base64url(ed25519Utils.bufferFromString(JSON.stringify(header))), splitted[1]);
  var signature = base64url(Buffer.from(ed25519.sign.detached(ed25519Utils.bufferFromString(securedInput), privateKey)));
  return util.format('%s.%s', securedInput, signature);
}

module.exports = function (payload, secretOrPrivateKey, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else {
    options = options || {}; // may mutate later
  }

  function failure(err) {
    if (callback) {
      return callback(err);
    }
    throw err;
  }

  // secretOrPrivateKey may be an object of the format: { "algorithm": ..., "key": ... }
  if (secretOrPrivateKey && secretOrPrivateKey.algorithm) {
    if (options.algorithm) {
      if (options.algorithm !== secretOrPrivateKey.algorithm) {
        return failure(new Error('The algorithm specified in the key is different from the algorithm specified in the options'));
      }
    } else {
      options.algorithm = secretOrPrivateKey.algorithm;
    }
    secretOrPrivateKey = secretOrPrivateKey.key;
  }

  var isObjectPayload = typeof payload === 'object' &&
                        !Buffer.isBuffer(payload);

  var header = Object.assign({
    alg: options.algorithm || 'HS256',
    typ: isObjectPayload ? 'JWT' : undefined,
    kid: options.keyid
  }, options.header);

  if (!secretOrPrivateKey && options.algorithm !== 'none') {
    return failure(new Error('secretOrPrivateKey must have a value'));
  }

  if (typeof payload === 'undefined') {
    return failure(new Error('payload is required'));
  } else if (isObjectPayload) {
    try {
      validatePayload(payload);
    }
    catch (error) {
      return failure(error);
    }
    if (!options.mutatePayload) {
      payload = Object.assign({},payload);
    }
  } else {
    var invalid_options = options_for_objects.filter(function (opt) {
      return typeof options[opt] !== 'undefined';
    });

    if (invalid_options.length > 0) {
      return failure(new Error('invalid ' + invalid_options.join(',') + ' option for ' + (typeof payload ) + ' payload'));
    }
  }

  if (typeof payload.exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
    return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
  }

  if (typeof payload.nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
    return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
  }

  try {
    validateOptions(options);
  }
  catch (error) {
    return failure(error);
  }

  var timestamp = payload.iat || Math.floor(Date.now() / 1000);

  if (!options.noTimestamp) {
    payload.iat = timestamp;
  } else {
    delete payload.iat;
  }

  if (typeof options.notBefore !== 'undefined') {
    payload.nbf = timespan(options.notBefore, timestamp);
    if (typeof payload.nbf === 'undefined') {
      return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
    payload.exp = timespan(options.expiresIn, timestamp);
    if (typeof payload.exp === 'undefined') {
      return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
    }
  }

  Object.keys(options_to_payload).forEach(function (key) {
    var claim = options_to_payload[key];
    if (typeof options[key] !== 'undefined') {
      if (typeof payload[claim] !== 'undefined') {
        return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
      }
      payload[claim] = options[key];
    }
  });

  var encoding = options.encoding || 'utf8';

  var isEd25519 = false;
  if (header.alg === 'Ed25519') {
    isEd25519 = true;
    try {
      secretOrPrivateKey = ed25519Utils.toPrivateKey(secretOrPrivateKey);
    } catch (err) {
      return failure(new Error('Invalid Ed25519 private key'));
    }
    header.alg = 'none';
  }

  if (typeof callback === 'function') {
    callback = callback && once(callback);

    jws.createSign({
      header: header,
      privateKey: (isEd25519 ? '' : secretOrPrivateKey),
      payload: payload,
      encoding: encoding
    }).once('error', callback)
      .once('done', function (signature) {
        if (isEd25519) {
          try {
            signature = fixEd25519Signature(signature, secretOrPrivateKey);
          } catch (err) {
            return callback(err);
          }
        }
        callback(null, signature);
      });
  } else {
    var signature = jws.sign({header: header, payload: payload, secret: (isEd25519 ? '' : secretOrPrivateKey), encoding: encoding});
    return (isEd25519 ? fixEd25519Signature(signature, secretOrPrivateKey) : signature);
  }
};
