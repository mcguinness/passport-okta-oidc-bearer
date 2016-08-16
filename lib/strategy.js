'use strict';

var _ = require('lodash');
var util = require('util');
var passport = require('passport-strategy');
var Promise = require('bluebird');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var MetadataProvider = require('./metadata-provider');
var JWT = Promise.promisifyAll(require('jsonwebtoken'));
var log = require('./logging').getLogger('Passport OAuth2 JWT Bearer Strategy');

var verifyJwt = async(function(token, options) {
  var key;

  var decodedJwt = JWT.decode(token, {complete: true});
  if (!_.isObject(decodedJwt)) {
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

  if (!_.isObject(key)) {
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
  if (!verify) { throw new TypeError('Strategy requires a verify callback'); }
  this._verify = verify;

  // if logging level specified, switch to it.
  if (options.loggingLevel) {
    log.levels("console", options.loggingLevel);
  }

  this._realm = options.realm || options.audience

  if (!options.issuer) {
    throw new TypeError('options.issuer is a required argument to verify a token');
  }
  this._issuer = options.issuer;

  if (!options.audience) {
    throw new TypeError('options.audience is a required argument to verify a token');
  }
  this._audience = options.audience;

  if (options.metadataProvider && _.isFunction(options.metadataProvider.getKey)) {
    this._metadataProvider = options.metadataProvider;
  }
  else if (options.metadataUrl) {
    this._metadataProvider = Promise.promisifyAll(new MetadataProvider(options.metadataUrl, options));
  } else {
    throw new TypeError('options.metadataUrl or options.metadataProvider is a required argument to verify a token');
  }

  passport.Strategy.call(this);
  this.name = 'oauth2-jwt-bearer';

  log.info({
    issuer: this._issuer,
    audience: this._audience,
    realm: this._realm,
    metadataUrl: options.metadataUrl
  }, 'Inititalized strategy with options');
};


/**
 * Inherit from `BearerStrategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request based on the contents of a JWT HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var self = this;
  var token;

  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length == 2) {
      var scheme = parts[0]
        , credentials = parts[1];

      if (/^Bearer$/i.test(scheme)) {
        token = credentials;
      }
    } else {
      return self._challenge({
        code: 'invalid_request',
        description: 'request must specify a valid scheme and token',
        uri: 'https://tools.ietf.org/html/rfc6750'
      }, 400);
    }
  }

  if (req.body && req.body.access_token) {
    if (token) {
      return self._challenge({
        code: 'invalid_request',
        description: 'request cannot have token in both authorization header and post param',
        uri: 'https://tools.ietf.org/html/rfc6750'
      }, 400);
    }
    token = req.body.access_token;
  }

  if (req.query && req.query.access_token) {
    if (token) {
      return self._challenge({
        code: 'invalid_request',
        description: 'request cannot have token in both authorization header and query param',
        uri: 'https://tools.ietf.org/html/rfc6750'
      }, 400);
    }
    token = req.query.access_token;
  }

  if (!token) {
    return self._challenge({
      code: 'invalid_request',
      description: 'request must specify an access_token',
      uri: 'https://tools.ietf.org/html/rfc6750'
    }, 400);
  }

  verifyJwt(token, {
    issuer: self._issuer,
    audience: self._audience,
    metadataProvider: self._metadataProvider
  })
  .then(function(claims) {
    log.debug({claims: claims}, 'Token is valid for request');
    if (options && (_.isArray(options.scopes) || _.isString(options.scopes))) {
      var requiredScopes = _.isArray(options.scopes) ? options.scopes : [options.scopes];
      var grantedScopes = _.intersectionBy(requiredScopes, claims.scp);
      if (requiredScopes.length !== grantedScopes.length) {
        return self._challenge({
          code: 'insufficient_scope',
          scopes: requiredScopes,
          description: 'Insufficient scope for this resource'
        }, 403);
      }
    }

    if (self._passReqToCallback) {
      self._verify(req, claims, _.bind(self._postVerify, self));
    } else {
      self._verify(claims, _.bind(self._postVerify, self));
    }
  })
  .catch(function(err) {
    log.error({
      err: (err.inner && err.inner.message) ? err.inner : err
    }, 'Invalid token for request');
    return self._challenge({
      code: 'invalid_token',
      description: err.message
    }, 401);
  });
};

/**
 * Build authentication challenge.
 *
 * @api private
 */
Strategy.prototype._challenge = function(params, status) {
  var challenge = 'Bearer realm="' + this._realm + '"';
  if (params.scopes) {
    challenge += ', scope="' + params.scopes.join(' ') + '"';
  }
  if (params.code) {
    challenge += ', error="' + params.code + '"';
  }
  if (params.description && params.description.length) {
    challenge += ', error_description="' + params.description + '"';
  }
  if (params.uri && params.uri.length) {
    challenge += ', error_uri="' + params.uri + '"';
  }
  log.debug({params: params}, 'User not authorized and challenged for authentication');
  return this.fail(challenge, status);
};


Strategy.prototype._postVerify = function(err, user, info) {
  if (err) { return this.error(err); }
  if (!user) {
    if (_.isString(info)) {
      info = { message: info }
    }
    info = info || {};
    return this._challenge({
      code: 'invalid_token',
      description: info.message
    }, 401);
  }
  log.debug({user: user}, 'User successfully authorized for request');
  return this.success(user, info);
}


module.exports = Strategy;
