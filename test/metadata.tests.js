var assert = require('chai').assert;
var nock = require('nock');
var path = require('path');
var fs = require('fs');
var MetadataProvider = require('../lib/metadata-provider.js');

describe('MetadataProvider', function() {

  var issuer = 'https://example.oktapreview.com';
  var opMetadataPath = '/.well-known/openid-configuration';
  var jwksPath = '/oauth2/v1/keys';
  var kid ='C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY';

  beforeEach(function() {
    nock(issuer)
      .get(opMetadataPath)
      .replyWithFile(200, path.join(__dirname, 'openid-configuration.json'))
      .get(jwksPath)
      .replyWithFile(200, path.join(__dirname, 'keys.json'));
  });

  afterEach(function () {
    nock.cleanAll();
  });

  describe('#get()', function() {

    var provider = new MetadataProvider(issuer + opMetadataPath, {loggingLevel: 'debug'});

    it('should have OpenID Provider metadata with issuer and JWKS', function(done) {
      provider.get(function(err, metadata) {
        assert.equal(metadata.issuer, 'https://example.oktapreview.com');
        assert.equal(metadata.jwks_uri, 'https://example.oktapreview.com/oauth2/v1/keys');
        done();
      });
    });

    it('should have OpenID Provider metadata with key and PEM certificate', function(done) {
      provider.getKey(kid, function(err, key) {
        assert.isNull(err);
        assert.isNotNull(key);
        assert.isNotNull(key.pem);
        assert.equal(key.kid, kid);
        done();
      })
    });

  });
});
