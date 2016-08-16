/*jslint node: true */
'use strict';

var Promise = require('bluebird');
var pkg = require('../package.json');
var util = require('util');
var request = require('request-promise');
var async = require('asyncawait/async');
var await = require('asyncawait/await');
var log = require('./logging').getLogger('JWKS Metadata Provider');


request = request.defaults({
  headers: {
    'Accept': 'application/json',
    'User-Agent': pkg.name + ' ' + pkg.version
  },
  gzip: true,
  timeout: 15000,
  strictSSL: true,
  json: true,
  agentOptions: {
    securityOptions: 'SSL_OP_NO_SSLv3',
    ciphers: [
      "ECDHE-RSA-AES256-SHA384",
      "DHE-RSA-AES256-SHA384",
      "ECDHE-RSA-AES256-SHA256",
      "DHE-RSA-AES256-SHA256",
      "ECDHE-RSA-AES128-SHA256",
      "DHE-RSA-AES128-SHA256",
      "HIGH",
      "!aNULL",
      "!eNULL",
      "!EXPORT",
      "!DES",
      "!RC4",
      "!MD5",
      "!PSK",
      "!SRP",
      "!CAMELLIA"
    ].join(':'),
    honorCipherOrder: true
  }
});

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
  if (key.kty !== 'RSA') {
    throw new Error(util.format('Key %s must be type "RSA" but was "%s"', key.id, key.kty));
  }
  if (!key.n) {
    throw new Error(util.format('JWK %s is corrupt, the RSA modulus was empty', key.id));
  }
  if (!key.e) {
    throw new Error(util.format('JWK %s is corrupt, the RSA exponent was empty', key.id));
  }

  var modulus = new Buffer(key.n, 'base64');
  var exponent = new Buffer(key.e, 'base64');
  var pemKey = rsaPublicKeyToPem(modulus, exponent);
  return pemKey;
};


var getJwks = async(function(jwksUrl) {
  var keys;

  log.info({url: jwksUrl}, 'Downloading JWKS from %s', jwksUrl);
  var res = await(request({
    method: "GET",
    url: jwksUrl,
    resolveWithFullResponse: true
  }));

  if (res.statusCode !== 200) {
    log.error({url: jwksUrl, res: res}, 'Unable to download JWKS from %s', jwksUrl);
    throw new Error('Unable to download JWKS from "' + jwksUrl + '" due to HTTP StatusCode ' +
      res.statusCode);
  }

  keys = res.body && res.body.keys ? res.body.keys : [];

  log.info({
    res: res,
    jwks: keys
  }, 'Successfully downloaded JWKS from %s', jwksUrl);

  keys.forEach(function(key) {
    if (key.kty === 'RSA' && key.use === 'sig') {
      log.debug({key: key}, 'Converting RSA key to PEM');
      key.pem = jwkToPem(key);
    }
  })

  return keys;
});

var getMetadata = async(function(metadataUrl) {
  var metadata;

  log.info({url: metadataUrl}, 'Downloading metadata from %s', metadataUrl);
  var res = await(request({
    method: "GET",
    url: metadataUrl,
    resolveWithFullResponse: true
  }));

  if (res.statusCode !== 200) {
    log.error({url: metadataUrl, res: res}, 'Unable to retrieve metadata');
    throw new Error('Unable to retrieve metadata from "' + metadataUrl + '" due to HTTP StatusCode ' +
      res.statusCode);
  }

  metadata = res.body || {};

  log.info({
    res: res,
    metadata: metadata,
    serverCert: res.socket.getPeerCertificate()
  }, 'Successfully downloaded metadata from %s', metadataUrl);

  if (metadata.jwks_uri) {
    metadata._keys = await(getJwks(metadata.jwks_uri));
  }

  metadata._lastUpdated = new Date();

  return metadata;
});


var MetadataProvider = function(url, options) {
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
};

Object.defineProperty(MetadataProvider, 'url', {
  get: function() {
    return this.url;
  }
});

MetadataProvider.prototype.getKey = function(kid, callback) {
  this.get(function(err, metadata) {
    if (err) {
      return callback(err);
    }

    log.debug(
      {
        kid: kid,
        jwks: metadata._keys
      },
      'Resolving kid %s with cached JWKS (last updated: %s)', kid, metadata._lastUpdated.toISOString()
    );

    for (var i=0; i<metadata._keys.length; i++) {
      if (metadata._keys[i].kid === kid) {
        return callback(null, metadata._keys[i]);
      }
    }
    return callback(null);
  })
};


MetadataProvider.prototype.get = function(options, callback) {
  var self = this;

  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  if (options.refresh || !self.metadata) {
    getMetadata(this.url)
      .then(function(metadata) {
        self.metadata = metadata;
        log.info({metadata: metadata}, 'Caching downloaded metadata');
        return callback(null, metadata);
      })
      .catch(function(err) {
        log.error({
          err: err
        }, 'Failed to download metadata from %s', self.url);
        return callback(err);
      });
  } else {
    return callback(null, self.metadata);
  }
};

module.exports = MetadataProvider;
