var chai = require('chai');
chai.use(require('chai-passport-strategy'));
var assert = chai.assert;
var expect = chai.expect;
var sinon = require('sinon');
var path = require('path');
var fs = require('fs');
var Metadata = require('../lib/metadata.js');
var Strategy = require('../lib/strategy.js');

describe('Strategy', function() {

  var issuer = 'https://example.oktapreview.com';
  var oidcConfigPath = '/.well-known/openid-configuration';
  var oidcConfig = fs.readFileSync(path.join(__dirname, 'openid-configuration.json'), 'utf8');
  var jwkPath = '/oauth2/v1/keys';
  var jwk = fs.readFileSync(path.join(__dirname, 'keys.json'), 'utf8');
  var id_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkM0TmdMMlFIVHpvRVJfbzEzTGJza2pYWk1RV1FoUVRZZzNvdFBHR1pHWFkifQ.eyJzdWIiOiIwMHU1aXZzdnI1MzFVNWRoajBoNyIsIm5hbWUiOiJLYXJsIE1jR3Vpbm5lc3MiLCJsb2NhbGUiOiJlbi1VUyIsImVtYWlsIjoia21jZ3Vpbm5lc3NAb2t0YS5jb20iLCJ2ZXIiOjEsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5va3RhcHJldmlldy5jb20iLCJhdWQiOiJBTlJaaHlEaDhIQkZONWFiTjZSZyIsImlhdCI6MTQ2MDMxMzUxMiwiZXhwIjoxNDYwMzE3MTEyLCJqdGkiOiJGekFqdS14RVhaa2ZWSTJudmstdiIsImFtciI6WyJwd2QiXSwiaWRwIjoiMDBvNWl2c3ZxbEpTSlZCbWUwaDciLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJrbWNndWlubmVzc0Bva3RhLmNvbSIsImdpdmVuX25hbWUiOiJLYXJsIiwiZmFtaWx5X25hbWUiOiJNY0d1aW5uZXNzIiwiem9uZWluZm8iOiJBbWVyaWNhL0xvc19BbmdlbGVzIiwidXBkYXRlZF9hdCI6MTQ1NzgzNDk1MiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF1dGhfdGltZSI6MTQ2MDMxMzUxMn0.cxx2NHLcN8-Fabbw3GfcfQYJut0s6dvhPBokvL2eZlXEz1PlC6uronOT55E8qLf4PgQbuSqiW9HQHtp6ollRGJzPGzjEvociHh9LnHmK8p2EUBS_JcddXuH2UxYbCFo45lp-wMhHUEQGaQaMzuNscIju2Xy93Dv9rCsl826hE1vNZAoiYpvLBlGF2rUE_w4RmZSIzbDYBe5ueBtTzM1KaLgIXExNXqHhsyHv2MZV5Mz0UUcg66P2HwEgDWoHHZQhx11u57-3Bd_S1PxIcM-EAtMhnj0onr588muaACgeVAh8P3-kK3MvzqhHBIMQCwUbmDO4b5DYcj3xaYVHq62Raw';
  var kid ='C4NgL2QHTzoER_o13LbskjXZMQWQhQTYg3otPGGZGXY';
  var expiresAt = 1460313512;
  var audience = 'ANRZhyDh8HBFN5abN6Rg';
  var subject = '00u5ivsvr531U5dhj0h7';
  var email = 'kmcguinness@okta.com';
  var strategy = new Strategy({
    audience: audience,
    metadataUrl: issuer + oidcConfigPath,
    loggingLevel: 'debug'
  }, function(token, done) {
    // done(err, user, info)
    return done(null, token);
  });

  var server;
  var clock;

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
    try { clock.restore(); } catch (e) {}
  });

  describe('valid id_token bearer request', function() {
    var user;
    var info;

    before(function(done) {
      clock = sinon.useFakeTimers((expiresAt - 60) * 1000);
      chai.passport.use(strategy)
        .success(function(u, i) {
          user = u;
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'BEARER ' + id_token;
        })
        .authenticate();
    });

    it('should not be expired', function() {
      expect(user).to.be.an.object;
      expect(user.sub).to.equal(subject);
    });
  });

  describe('invalid id_token bearer request', function() {

    describe('with expired token', function() {
      var challenge;

      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'BEARER ' + id_token;
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
          expect(challenge).to.be.a.string;
          expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_token", error_description="The access token is expired"');
      });
    });

    describe('with invalid token', function() {
      var challenge;

      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(c) {
            challenge = c;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Bearer WRONG';
          })
          .authenticate();
      });

      it('should fail with challenge', function() {
        expect(challenge).to.be.a.string;
        expect(challenge).to.equal('Bearer realm="OIDC", error="invalid_token", error_description="The access token is not a valid JWT"');
      });
    });
  });
});
