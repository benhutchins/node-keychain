/* global describe, it */
var keychain = require('../')

describe('KeychainAccess', function () {
  var testService = 'KeychainAccess#test#' + Date.now()

  var asciiPW = 'test'
  var mixedPW = '∆elta'
  var unicodePW = '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥'

  it('should be running on a mac', function () {
    require('os').platform().should.equal('darwin')
  })

  describe('.setPassword(opts, fn)', function () {
    describe('when no account is given', function () {
      it('should return an error', function (done) {
        keychain.setPassword({ password: 'baz', service: testService }, function (err) {
          err.should.be.instanceOf(Error)
          err.code.should.equal('NoAccountProvided')
          done()
        })
      })
    })

    describe('when no service is given', function () {
      it('should return an error', function (done) {
        keychain.setPassword({ account: 'foo', password: 'baz' }, function (err) {
          err.should.be.instanceOf(Error)
          err.code.should.equal('NoServiceProvided')
          done()
        })
      })
    })

    describe('when no password is given', function () {
      it('should return an error', function (done) {
        keychain.setPassword({ account: 'foo', service: testService }, function (err) {
          err.should.be.instanceOf(Error)
          err.code.should.equal('NoPasswordProvided')
          done()
        })
      })
    })

    describe('when a password is given', function () {
      var params = { account: 'asciiAccount', password: asciiPW, service: testService }
      it('should should be a success', function (done) {
        keychain.setPassword(params, function (err) {
          (err === null).should.be.true
          done()
        })
      })
    })

    describe('when a unicode password is set', function () {
      var params = { account: 'unicodeAccount', password: unicodePW, service: testService }
      it('should should be a success', function (done) {
        keychain.setPassword(params, function (err) {
          (err === null).should.be.true
          done()
        })
      })
    })

    describe('when sent mixed unicode password is set', function () {
      var params = { account: 'mixedAccount', password: mixedPW, service: testService }
      it('should should be a success', function (done) {
        keychain.setPassword(params, function (err) {
          (err === null).should.be.true
          done()
        })
      })
    })
  })

  describe('.getPassword(opts, fn)', function () {
    describe('when no account is given', function () {
      it('should return an error', function (done) {
        keychain.getPassword({ password: 'baz', service: testService }, function (err) {
          err.should.be.instanceOf(Error).and.have.property('code', 'NoAccountProvided')
          done()
        })
      })
    })

    describe('when no service is given', function () {
      it('should return an error', function (done) {
        keychain.getPassword({ account: 'foo', password: 'baz' }, function (err) {
          err.should.be.instanceOf(Error).and.have.property('code', 'NoServiceProvided')
          done()
        })
      })
    })

    describe('when a password is requested', function () {
      var params = { account: 'asciiAccount', service: testService }
      it('should return the password', function (done) {
        keychain.getPassword(params, function (err, pass) {
          (err === null).should.be.true
          pass.should.equal(asciiPW)
          done()
        })
      })
    })

    describe('when a non-existent password is requested', function () {
      var params = { account: 'asciiAccount', service: testService + '#NOTEXIST' }
      it('should return an error', function (done) {
        keychain.getPassword(params, function (err, pass) {
          err.should.be.instanceOf(Error).and.have.property('code', 'PasswordNotFound')
          done()
        })
      })
    })

    describe('when a unicode password is requested', function () {
      var params = { account: 'unicodeAccount', service: testService }
      it('should return the password', function (done) {
        keychain.getPassword(params, function (err, pass) {
          (err === null).should.be.true
          pass.should.equal(unicodePW)
          done()
        })
      })
    })

    describe('when a mixed unicode password is requested', function () {
      var params = { account: 'mixedAccount', service: testService }
      it('should return the password', function (done) {
        keychain.getPassword(params, function (err, pass) {
          (err === null).should.be.true
          pass.should.equal(mixedPW)
          done()
        })
      })
    })
  })

  describe('.deletePassword(opts, fn)', function () {
    describe('when no account is given', function () {
      it('should return an error', function (done) {
        keychain.deletePassword({ password: 'baz', service: testService }, function (err) {
          err.should.be.instanceOf(Error).and.have.property('code', 'NoAccountProvided')
          done()
        })
      })
    })

    describe('when no service is given', function () {
      it('should return an error', function (done) {
        keychain.deletePassword({ account: 'foo', password: 'baz' }, function (err) {
          err.should.be.instanceOf(Error).and.have.property('code', 'NoServiceProvided')
          done()
        })
      })
    })

    describe('when a password is deleted', function () {
      var params = { account: 'asciiAccount', service: testService }
      it('should delete it', function (done) {
        keychain.deletePassword(params, function (err) {
          (err === null).should.be.true
          done()
        })
      })
    })

    describe('when sent the same options again', function () {
      var params = { account: 'asciiAccount', service: testService }
      it('should return an error', function (done) {
        keychain.deletePassword(params, function (err) {
          err.should.be.instanceOf(Error).and.have.property('code', 'PasswordNotFound')
          done()
        })
      })
    })
  })
})
