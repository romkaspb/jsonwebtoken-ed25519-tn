module.exports = {
  decode: require('./decode'),
  verify: require('./verify'),
  sign: require('./sign'),
  toJWK: require('./lib/toJWK'),
  JsonWebTokenError: require('./lib/JsonWebTokenError'),
  NotBeforeError: require('./lib/NotBeforeError'),
  TokenExpiredError: require('./lib/TokenExpiredError'),
};
