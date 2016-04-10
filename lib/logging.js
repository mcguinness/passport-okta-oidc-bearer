'use strict';

var bunyan = require('bunyan');

module.exports.getLogger = function(name) {
  return bunyan.createLogger({
    name: name,
    streams: [
      {
        stream: process.stderr,
        level: 'error',
        name: 'error'
      }, {
        stream: process.stdout,
        level: 'warn',
        name: 'console'
      }
    ]
  });
};
