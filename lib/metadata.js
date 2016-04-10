/*jslint node: true */
'use strict';

var util = require('util');
var request = require('request');
var async = require('async');
var log = require('./logging').getLogger('OIDC Metadata Parser');

//http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js
function rsaPublicKeyToPem(modulus_b64, exponent_b64) {

    var modulus = new Buffer(modulus_b64, 'base64');
    var exponent = new Buffer(exponent_b64, 'base64');

    var modulus_hex = modulus.toString('hex');
    var exponent_hex = exponent.toString('hex');

    modulus_hex = prepadSigned(modulus_hex);
    exponent_hex = prepadSigned(exponent_hex);

    var modlen = modulus_hex.length/2;
    var explen = exponent_hex.length/2;

    var encoded_modlen = encodeLengthHex(modlen);
    var encoded_explen = encodeLengthHex(explen);
    var encoded_pubkey = '30' +
        encodeLengthHex(
            modlen +
            explen +
            encoded_modlen.length/2 +
            encoded_explen.length/2 + 2
        ) +
        '02' + encoded_modlen + modulus_hex +
        '02' + encoded_explen + exponent_hex;

    var der_b64 = new Buffer(encoded_pubkey, 'hex').toString('base64');

    var pem = '-----BEGIN RSA PUBLIC KEY-----\n' +
    der_b64.match(/.{1,64}/g).join('\n') +
    '\n-----END RSA PUBLIC KEY-----\n';

    return pem;
};

/*jshint latedef: nofunc */
function prepadSigned(hexStr) {
    var msb = hexStr[0];
    if (msb < '0' || msb > '7') {
        return '00'+hexStr;
    } else {
        return hexStr;
    }
}

function toHex(number) {
    var nstr = number.toString(16);
    if (nstr.length%2)  { return '0'+nstr; }
    return nstr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n) {
    if (n<=127) { return toHex(n); }
    else {
        var n_hex = toHex(n);
        var length_of_length_byte = 128 + n_hex.length/2; // 0x80+numbytes
        return toHex(length_of_length_byte)+n_hex;
    }
}

function jwkToPem(key) {
  log.info('Generating PEM for JWK: ', key);
  if (!key.n) {
    log.warn('JWK is corrupt, the modulus was empty');
    return null;
  } else if (!key.e) {
    log.warn('JWK is corrupt, the exponent was empty was empty');
    return null;
  } else {
    var modulus = new Buffer(key.n, 'base64');
    var exponent = new Buffer(key.e, 'base64');
    var pemKey = rsaPublicKeyToPem(modulus, exponent);
    log.debug("PEM: ", pemKey);
    return pemKey;
  }
};

var Metadata = function(url, options) {
  if (!url) {
    throw new Error("url is a required argument");
  }

  if (!options) {
    options = {};
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) {
    log.levels("console", options.loggingLevel);
  }

  this.url = url;
  this.metadata = {};
  this.metadata.keys = [];
};

Object.defineProperty(Metadata, 'url', {
  get: function() {
    return this.url;
  }
});

Object.defineProperty(Metadata, 'metadata', {
  get: function() {
    return this.metadata;
  }
});

Metadata.prototype.getKey = function(kid) {
  log.debug('Resolving kid=%s with OIDC Provider JWK', kid)
  var key;
  for (var i=0; i<this.metadata.keys.length; i++) {
    key = this.metadata.keys[i];
    if (key.kid === kid) {
      log.debug("Found key %s for kid=%s", key.x5t, kid);
      return key;
    }
  }
  log.warn('Unable to resolve kid=%s with OIDC Provider JWK (Updated: %s)',
    kid, this.metadata.lastUpdated);
  return null;
};

Metadata.prototype.getOrFetchKey = function(kid, callback) {
  var self = this;

  var key = self.getKey(kid);
  if (!util.isObject(key)) {
    self.fetch(function(err) {
      if (err) {
        return callback(err);
      }
      key = self.getKey(kid);
      if (!util.isObject(key)) {
        return callback(new Error(
          util.format('Unable to resolve kid=%s with OIDC Provider JWK (Updated: %s)',
            kid, this.metadata.lastUpdated)));
      }
      return callback(null, key);
    });
  } else {
    return callback(null, key);
  }
}

Metadata.prototype.update = function(metadata, callback) {
  var self = this;

  log.info('Updating OIDC Provider Metadata');

  try {
    metadata = util.isString(metadata) ?
      JSON.parse(metadata) :
      metadata;
  } catch (err) {
    return callback(new Error('Invalid OIDC Provider Metadata JSON: ' + err.message));
  }

  log.info('Metadata: ', metadata);

  async.waterfall([
    function(next) {
      log.debug('Fetching OIDC Provider JWK from %s', metadata.jwks_uri);
      request(metadata.jwks_uri, function(err, response, json) {
        if (err) {
          return next(err);
        } else if (response.statusCode !== 200) {
          return next(
            new Error('Unable to retrieve OIDC Provider JWK from %s (HTTP Status: %s)',
              metadata.jwks_uri,
              response.statusCode));
        } else {
          return next(null, json);
        }
      });
    },
    function(json, next) {
      log.debug('Parsing JWK for OIDC Provider');
      try {
        metadata.keys = JSON.parse(json).keys;
        log.debug('JWK: ', metadata.keys);
        metadata.keys.forEach(function(key) {
          key.pem = jwkToPem(key);
        })
        return next(null);
      } catch (err) {
        log.error(err, 'Unable to parse JWK for OIDC Provider');
        return next(err);
      }
    }
  ], function(err) {
    if (err) {
      log.error(err, 'Unable to process JWK for OIDC Provider');
      return callback(err);
    }
    // Save metadata
    metadata.lastUpdated = new Date();
    self.metadata = metadata;
    return callback(null, metadata);
  });
};

Metadata.prototype.fetch = function(callback) {
  var self = this;

  log.info('Fetching OIDC Provider Metadata from %s', self.url)

  async.waterfall([
    function(next) {
      request(self.url, function(err, response, json) {
        if (err) {
          return next(err);
        } else if (response.statusCode !== 200) {
          var msg = util.format('Unable to retrieve OIDC Provider Metadata from %s (HTTP Status: %s)',
            self.url, response.statusCode);
          log.error(msg);
          return next(new Error(msg));
        } else {
          return next(null, json);
        }
      });
    },
    function(json, next) {
      log.debug('Processing OIDC Provider Metadata', json);
      return self.update(json, next);
    }
  ], function(err) {
    if (err) {
      log.error(err);
    }
    return callback(err);
  });
};

module.exports = Metadata;
