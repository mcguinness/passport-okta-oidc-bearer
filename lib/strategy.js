'use strict';

var BearerStrategy = require('passport-http-bearer').Strategy;
var Metadata = require('./metadata');
var util = require('util');
var async = require('async');
var jwt = require('jsonwebtoken');
var log = require('./logging').getLogger("Passport OIDC Bearer Strategy");

function Strategy(options, verify) {
  /*jshint validthis: true */

  log.info('Initializing Stategy');

  if (typeof options === 'function') {
    verify = options;
    options = {};
  }

  // Passport requires a verify function
  if (!verify) {
    throw new TypeError('Strategy requires a verify callback. Do not cheat!');
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) {
    log.levels("console", options.loggingLevel);
  }

  if (!options.realm) {
    options.realm = 'OIDC';
  }

  log.info('Audience: ', options.audience);
  log.info('OIDC Provider Metadata URL: ', options.metadataUrl);

  if (options.metadataUrl) {
    this.metadata = new Metadata(options.metadataUrl, options);
  } else {
    throw new Error('Strategy requires an OIDC Provider Metadata URL.');
  }

  function jwtVerify(req, token, callback) {

    var self = this;
    var _options = options;

    if (!options.passReqToCallback) {
      token = arguments[0];
      callback = arguments[1];
      req = null;
    }

    log.debug('Verifying access token %s', token);

    var decoded = jwt.decode(token, {complete: true});
    if (decoded == null) {
      return callback(null, false, 'The access token is not a valid JWT');
    }
    log.debug('Decoded JWT: ', decoded);

    async.waterfall([
      function(next) {
        if (!util.isObject(decoded.header) || !util.isString(decoded.header.kid)) {
          return next(new Error('Access token must specify a valid JWT header with JWK ID'));
        } else {
          return self.metadata.getOrFetchKey(decoded.header.kid, next);
        }
      },
      function(key, next) {
        if (!util.isObject(key)) {
          return next(new Error('Unable to resolve JWK for access token signature (kid=' + decoded.header.kid + ')'));
        }
        jwt.verify(token, key.pem, {
          algorithms: key.alg,
          issuer: self.metadata.issuer,
          audience: options.audience
        }, next);
      }
    ], function(err, payload) {
      if (err) {
        log.warn(err, 'Failed to verify JWT');
        if (err instanceof jwt.TokenExpiredError) {
          return callback(null, false, 'The access token is expired');
        } else if (err instanceof jwt.JsonWebTokenError) {
          return callback(null, false, 'The access token is not valid: %s', err.message);
        } else {
          return callback(err, false);
        }
      } else {
        log.info('The access token is valid', payload);
        if (options.passReqToCallback) {
         return verify(req, payload, callback);
        } else {
          return verify(payload, callback);
        }
      }
    })
  };

  BearerStrategy.call(this, options, jwtVerify);
  this.name = 'okta-oidc-bearer';
};


util.inherits(Strategy, BearerStrategy);

module.exports = Strategy;
