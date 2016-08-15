'use strict';

var util = require('util');
var Promise = require('bluebird');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var BearerStrategy = require('passport-http-bearer').Strategy;
var MetadataProvider = require('./metadata-provider');
var JWT = Promise.promisifyAll(require('jsonwebtoken'));
var log = require('./logging').getLogger('Passport OAuth2 JWT Bearer Strategy');


function isObject(value) {
  var type = typeof value;
  return !!value && (type == 'object' || type == 'function');
}

var verifyJwt = async(function(token, options) {
  var key;

  var decodedJwt = JWT.decode(token, {complete: true});
  if (!isObject(decodedJwt)) {
    throw new JWT.JsonWebTokenError('The token is not a valid JWT');
  }

  log.debug({access_token: decodedJwt}, 'Verifying JWT bearer token');

  if (decodedJwt.header && decodedJwt.header.kid) {
    try {
      key = await(options.metadataProvider.getKeyAsync(decodedJwt.header.kid));
    } catch (err) {
      throw new JWT.JsonWebTokenError('Unable to resolve key for token signature', err);
    }
  } else {
    throw new JWT.JsonWebTokenError('Token must specify a "kid" (Key ID) header parameter');
  }

  if (!isObject(key)) {
    throw new JWT.JsonWebTokenError('Unable to resolve key for token signature');
  }

  try {
    var claims = await(JWT.verify(token, key.pem, {
      algorithms: key.alg,
      issuer: options.issuer,
      audience: options.audience
    }));
    return claims;
  } catch (err) {
    if (err instanceof JWT.TokenExpiredError) {
      throw new JWT.JsonWebTokenError('The token is expired', err);
    } else if (err instanceof JWT.NotBeforeError) {
      throw new JWT.JsonWebTokenError('The token may not be used as this time but may be valid in the future', err);
    } else {
      throw new JWT.JsonWebTokenError('The token is not valid', err);
    }
  }
});


/**
 * Creates an instance of `Strategy`.
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the bearer token provided as a credential.  The verify callback
 * is responsible for finding the user who posesses the token, and invoking
 * `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `realm`  authentication realm, defaults to "Users"
 *   - `scope`  list of scope values indicating the required scope of the access
 *              token for accessing the requested resource
 *
 * Examples:
 *
 *     passport.use(new JwtBearerStrategy(
 *       function(claims, done) {
 *         User.findBySubject({ id: claims.sub }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, { scope: 'read' });
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @constructor
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  /*jshint validthis: true */

  var self = this;

  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  this._postVerify = verify;

  // if logging level specified, switch to it.
  if (options.loggingLevel) {
    log.levels("console", options.loggingLevel);
  }

  if (!options.realm) {
    options.realm = options.audience;
  }

  if (!options.issuer) {
    throw new TypeError('options.issuer is a required argument to verify a token');
  }
  this._issuer = options.issuer;


  if (!options.audience) {
    throw new TypeError('options.audience is a required argument to verify a token');
  }
  this._audience = options.audience;

  if (options.metadataProvider && options.metadataProvider.getKey &&
    typeof options.metadataProvider.getKey === 'function') {
    this._metadataProvider = options.metadataProvider;
  }
  else if (options.metadataUrl) {
    this._metadataProvider = Promise.promisifyAll(new MetadataProvider(options.metadataUrl, options));
  } else {
    throw new TypeError('options.metadataUrl or options.metadataProvider is a required argument to verify a token');
  }

  BearerStrategy.call(this, {
    realm: options.realm,
    scope: options.scope,
    passReqToCallback: true
  }, this._verifyToken);

  log.info({
    issuer: this._issuer,
    audience: this._audience,
    realm: this._realm,
    metadataUrl: options.metadataUrl
  }, 'Inititalized strategy with options')

  this.name = 'jwt-bearer';
};


/**
 * Inherit from `BearerStrategy`.
 */
util.inherits(Strategy, BearerStrategy);


Strategy.prototype._verifyToken = function(req, token, callback) {
  var self = this;
  verifyJwt(token, {
    issuer: self._issuer,
    audience: self._audience,
    metadataProvider: self._metadataProvider
  })
  .then(function(claims) {
    log.info({req: req, claims: claims}, 'Successfully verified token for request');
    return callback(null, claims);
  })
  .catch(function(err) {
    log.error({
      req: req,
      err: (err.inner && err.inner.message) ? err.inner : err
    }, 'Failed to verify token for request');
    return self.fail(self._challenge('invalid_token', err.message))
  });
};


module.exports = Strategy;
