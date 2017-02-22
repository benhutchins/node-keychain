/*!
 * node-keyring
 *
 * Maintained by:
 *  Nicholas Penree <nick@penree.com>
 *  Benjamin Hutchins <ben@hutchins.co>
 *
 * @license MIT Licensed
 */

// Polyfill Buffer.from for Node < 4 that didn't have a #from method
if (!Buffer.from) {
  Buffer.from = function (data, encoding, len) {
    return new Buffer(data, encoding, len)
  }
}
// Between Node >=4 to < 4.5 Buffer.from was inherited from Uint8Array
// And behaved differently, it was backported in 4.5.
if (Buffer.from === Uint8Array.from) {
  throw new Error('Node >= 4.0.0 to < 4.5.0 are unsupported')
}

var errors = require('./lib/errors')

/**
 * Basic Keychain Access on Mac computers running Node.js
 *
 * @public
 * @class KeychainAccess
 */
function KeychainAccess () {
  if (process.platform === 'darwin') {
    this.platform = require('./lib/platforms/mac')
  }
}

/**
 * Retreive a password from the keychain.
 *
 * @public
 * @param {Object} opts Object containing `account` and `service`
 * @param {Function} fn Callback
 */
KeychainAccess.prototype.getPassword = function (opts, fn) {
  opts = opts || {}
  fn = fn || noop

  if (!process.platform) {
    return fn(new errors.UnsupportedPlatformError(null, process.platform))
  }

  if (!opts.account) {
    return fn(new errors.NoAccountProvidedError())
  }

  if (!opts.service) {
    return fn(new errors.NoServiceProvidedError())
  }

  opts.account = utf8safe.encode(opts.account)
  opts.service = utf8safe.encode(opts.service)

  this.platform.get(opts, function (err, password) {
    fn(err, password ? utf8safe.decode(password) : null)
  })
}

/**
 * Set/update a password in the keychain.
 *
 * @public
 * @param {Object} opts Object containing `account`, `service`, and `password`
 * @param {Function} fn Callback
 */
KeychainAccess.prototype.setPassword = function (opts, fn) {
  opts = opts || {}
  fn = fn || noop

  if (process.platform !== 'darwin') {
    return fn(new errors.UnsupportedPlatformError(null, process.platform))
  }

  if (!opts.account) {
    return fn(new errors.NoAccountProvidedError())
  }

  if (!opts.service) {
    return fn(new errors.NoServiceProvidedError())
  }

  if (!opts.password) {
    return fn(new errors.NoPasswordProvidedError())
  }

  opts.account = utf8safe.encode(opts.account)
  opts.service = utf8safe.encode(opts.service)
  opts.password = utf8safe.encode(opts.password)

  this.platform.set(opts, fn)
}

/**
 * Delete a password from the keychain.
 *
 * @public
 * @param {Object} opts Object containing `account`, `service`, and `password`
 * @param {Function} fn Callback
 */
KeychainAccess.prototype.deletePassword = function (opts, fn) {
  opts = opts || {}
  fn = fn || noop
  var err

  if (!this.platform) {
    err = new errors.UnsupportedPlatformError(null, process.platform)
    return fn(err, null)
  }

  if (!opts.account) {
    err = new errors.NoAccountProvidedError()
    return fn(err, null)
  }

  if (!opts.service) {
    err = new errors.NoServiceProvidedError()
    return fn(err, null)
  }

  opts.account = utf8safe.encode(opts.account)
  opts.service = utf8safe.encode(opts.service)

  this.platform.del(opts, fn)
}

var noop = function () {}
KeychainAccess.errors = errors

var utf8safe = {
  encode: function (str) {
    return new Buffer(str).toString('base64')
  },
  decode: function (str) {
    return new Buffer(str, 'base64').toString('utf8')
  }
}

/**
 * Expose new Keychain Access
 */
module.exports = new KeychainAccess()
