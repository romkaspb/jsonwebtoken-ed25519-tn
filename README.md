# jsonwebtoken-ed25519-tn

An implementation of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) with the help of [tweetnacl](https://github.com/dchest/tweetnacl-js).

This was developed against `draft-ietf-oauth-json-web-token-08`. It makes use of [node-jws](https://github.com/brianloveswords/node-jws)

## Fork Changes

This package is a fork of [jsonwebtoken-ed25519](https://www.npmjs.com/package/jsonwebtoken-ed25519) with the only one major change:  

It is based on [tweetnacl](https://github.com/dchest/tweetnacl-js) library, while origin library [jsonwebtoken-ed25519](https://www.npmjs.com/package/jsonwebtoken-ed25519) based on [ed25519](https://www.npmjs.com/package/ed25519). The package got the same API as the original library. Check it [here](https://www.npmjs.com/package/jsonwebtoken-ed25519).
