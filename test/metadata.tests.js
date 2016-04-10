var assert = require('chai').assert;
var sinon = require('sinon');
var path = require('path');
var fs = require('fs');
var Metadata = require('../lib/metadata.js');

describe('Metadata', function() {

  var issuer = 'https://example.oktapreview.com';
  var oidcConfigPath = '/.well-known/openid-configuration';
  var oidcConfig = fs.readFileSync(path.join(__dirname, 'openid-configuration.json'), 'utf8');
  var jwkPath = '/oauth2/v1/keys';
  var jwk = fs.readFileSync(path.join(__dirname, 'keys.json'), 'utf8');
  var kid ='C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY';
  var server;

  beforeEach(function() {
    server = sinon.fakeServer.create();
    server.respondWith('GET', oidcConfigPath,
      [
        200,
        { "Content-Type": "application/json" },
        oidcConfig
      ]);

    server.respondWith('GET', jwkPath,
      [
        200,
        { "Content-Type": "application/json" },
        jwk
      ]);
  });

  afterEach(function () {
    server.restore();
  });

  describe('#fetch()', function () {

    it('should have OIDC provider metadata with key and PEM certificate', function(done) {

      var oidcMetadata = new Metadata(issuer + oidcConfigPath, {loggingLevel: 'debug'});

      oidcMetadata.fetch(function(err) {
        assert.equal(oidcMetadata.metadata.issuer, 'https://example.oktapreview.com');
        assert.equal(oidcMetadata.metadata.jwks_uri, 'https://example.oktapreview.com/oauth2/v1/keys');

        var key = oidcMetadata.getKey(kid);
        assert.isNull(err);
        assert.isNotNull(key);
        assert.isNotNull(key.pem);
        assert.equal(key.kid, kid);

        done();
      })
    });
  });
});
