/*!
 * node-keyring
 *
 * Maintained by Benjamin Hutchins <ben@hutchins.co>
 * Originally forked off node-keychain by Nicholas Penree <nick@penree.com>
 *
 * @license MIT Licensed
 */

/**
 * Module dependencies.
 */
var ref = require('ref')
var ffi = require('ffi')

var voidPointer = ref.refType(ref.types.void)
var SecKeychainRef = voidPointer
var SecKeychainItemRef = voidPointer

var security = ffi.Library('/System/Library/Frameworks/Security.framework/Versions/A/Security', {
  'SecKeychainCopyDefault': ['int', [SecKeychainRef]],
  'SecKeychainFindGenericPassword': ['int', [
    SecKeychainRef, // CFTypeRef keychainOrArray
    'int', // UInt32 serviceNameLength
    'string', // const char *serviceName
    'int', // UInt32 accountNameLength
    'string', // const char *accountName
    'pointer', // UInt32 *passwordLength
    'pointer', // void * _Nullable *passwordData
    SecKeychainItemRef // SecKeychainItemRef  _Nullable *itemRef
  ]],
  'SecKeychainAddGenericPassword': ['int', [
    SecKeychainRef, // SecKeychainRef keychain
    'int', // UInt32 serviceNameLength
    'string', // const char *serviceName
    'int', // UInt32 accountNameLength
    'string', // const char *accountName
    'int', // UInt32 *passwordLength
    'string', // void * _Nullable *passwordData
    SecKeychainItemRef // SecKeychainItemRef  _Nullable *itemRef
  ]],
  'SecKeychainItemDelete': ['int', [
    SecKeychainItemRef
  ]]
}, null, {
  appendExtension: false
})
var noop = function () {}

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

/**
 * Basic Keychain Access on Mac computers running Node.js
 *
 * @class KeychainAccess
 * @api public
 */
function KeychainAccess () {
  this.executablePath = '/usr/bin/security'
}

/**
 * Retreive a password from the keychain.
 *
 * @param {Object} opts Object containing `account` and `service`
 * @param {Function} fn Callback
 * @api public
 */

KeychainAccess.prototype.getPassword = function (opts, fn) {
  opts = opts || {}
  opts.type = (opts.type || 'generic').toLowerCase()
  fn = fn || noop
  var err

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform)
    return fn(err, null)
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError()
    return fn(err, null)
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError()
    return fn(err, null)
  }

  var keychainRef = ref.alloc(SecKeychainRef)
  var exitStatus = security.SecKeychainCopyDefault(keychainRef)

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.ServiceFailureError())
  }

  var keychainDeref = keychainRef.deref()
  var passwordLength = ref.alloc(ref.types.uint32)
  var passwordData = ref.alloc('string')

  console.log('about to run security.SecKeychainFindGenericPassword')

  exitStatus = security.SecKeychainFindGenericPassword(
    keychainDeref, // null uses the user's default keychain
    opts.service.length, // UInt32 serviceNameLength
    opts.service, // const char *serviceName UTF8
    opts.account.length, // UInt32 accountNameLength
    opts.account, // const char *accountName UTF8
    passwordLength, // UInt32 *passwordLength
    passwordData, // void * _Nullable *passwordData
    null // SecKeychainItemRef  _Nullable *itemRef
  )

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.PasswordNotFoundError())
  }

  console.log('ran security.SecKeychainFindGenericPassword')
  console.log(passwordData, passwordLength)

  var passwordDeref = passwordData.deref()
  var password = passwordDeref.toString('utf8')
  console.log(password)

  // When keychain escapes a char into octal it also includes a hex
  // encoded version.
  //
  // e.g. password 'passWith\' becomes:
  // password: 0x70617373576974685C  "passWith\134"
  //
  // And if the password does not contain ASCII it leaves out the quoted
  // version altogether:
  //
  // e.g. password '∆˚ˆ©ƒ®∂çµ˚¬˙ƒ®†¥' becomes:
  // password: 0xE28886CB9ACB86C2A9C692C2AEE28882C3A7C2B5CB9AC2ACCB99C692C2AEE280A0C2A5
  if (/0x([0-9a-fA-F]+)/.test(password)) {
    var hexPassword = password.match(/0x([0-9a-fA-F]+)/, '')[1]
    fn(null, Buffer.from(hexPassword, 'hex').toString())
  } else {
    fn(null, password)
  }
}

/**
 * Set/update a password in the keychain.
 *
 * @param {Object} opts Object containing `account`, `service`, and `password`
 * @param {Function} fn Callback
 * @api public
 */

KeychainAccess.prototype.setPassword = function (opts, fn) {
  opts = opts || {}
  opts.type = (opts.type || 'generic').toLowerCase()
  fn = fn || noop
  var err

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform)
    return fn(err, null)
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError()
    return fn(err, null)
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError()
    return fn(err, null)
  }

  if (!opts.password) {
    err = new KeychainAccess.errors.NoPasswordProvidedError()
    return fn(err, null)
  }

  var keychainRef = ref.alloc(SecKeychainRef)
  var exitStatus = security.SecKeychainCopyDefault(keychainRef)

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.ServiceFailureError())
  }

  var keychainDeref = keychainRef.deref()

  console.log('about to run security.SecKeychainFindGenericPassword')

  exitStatus = security.SecKeychainAddGenericPassword(
    keychainDeref, // null uses the user's default keychain
    opts.service.length, // UInt32 serviceNameLength
    opts.service, // const char *serviceName UTF8
    opts.account.length, // UInt32 accountNameLength
    opts.account, // const char *accountName UTF8
    opts.password.length, // UInt32 *passwordLength
    opts.password, // void * _Nullable *passwordData
    null // SecKeychainItemRef  _Nullable *itemRef
  )

  if (exitStatus === 45) {
    this.deletePassword(opts, function (err) {
      if (err) {
        return fn(err)
      }

      this.setPassword(opts, fn)
    }.bind(this))
  } else if (exitStatus !== 0) {
    fn(new KeychainAccess.errors.ServiceFailureError(null, exitStatus))
  } else {
    fn(null)
  }
}

/**
 * Delete a password from the keychain.
 *
 * @param {Object} opts Object containing `account`, `service`, and `password`
 * @param {Function} fn Callback
 * @api public
 */

KeychainAccess.prototype.deletePassword = function (opts, fn) {
  opts = opts || {}
  opts.type = (opts.type || 'generic').toLowerCase()
  fn = fn || noop
  var err

  if (process.platform !== 'darwin') {
    err = new KeychainAccess.errors.UnsupportedPlatformError(null, process.platform)
    return fn(err, null)
  }

  if (!opts.account) {
    err = new KeychainAccess.errors.NoAccountProvidedError()
    return fn(err, null)
  }

  if (!opts.service) {
    err = new KeychainAccess.errors.NoServiceProvidedError()
    return fn(err, null)
  }

  var keychainRef = ref.alloc(SecKeychainRef)
  var exitStatus = security.SecKeychainCopyDefault(keychainRef)

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.ServiceFailureError())
  }

  var keychainDeref = keychainRef.deref()
  var itemRef = ref.alloc(SecKeychainItemRef)

  console.log('about to run security.SecKeychainFindGenericPassword')

  exitStatus = security.SecKeychainFindGenericPassword(
    keychainDeref, // null uses the user's default keychain
    opts.service.length, // UInt32 serviceNameLength
    opts.service, // const char *serviceName UTF8
    opts.account.length, // UInt32 accountNameLength
    opts.account, // const char *accountName UTF8
    null, // UInt32 *passwordLength
    null, // void * _Nullable *passwordData
    itemRef // SecKeychainItemRef  _Nullable *itemRef
  )

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.ServiceFailureError(null, exitStatus))
  }

  exitStatus = security.SecKeychainItemDelete(itemRef)

  if (exitStatus !== 0) {
    return fn(new KeychainAccess.errors.ServiceFailureError(null, exitStatus))
  }

  fn(null)
}

function errorClass (code, defaultMsg) {
  var errorType = code + 'Error'
  var ErrorClass = function (msg, append) {
    this.type = errorType
    this.code = code
    this.message = (msg || defaultMsg) + (append || '')
    this.stack = (new Error()).stack
  }

  ErrorClass.prototype = Object.create(Error.prototype)
  ErrorClass.prototype.constructor = ErrorClass
  KeychainAccess.errors[errorType] = ErrorClass
}

KeychainAccess.errors = {}
errorClass('UnsupportedPlatform', 'Expected darwin platform, got: ')
errorClass('NoAccountProvided', 'An account is required')
errorClass('NoServiceProvided', 'A service is required')
errorClass('NoPasswordProvided', 'A password is required')
errorClass('ServiceFailure', 'Keychain failed to start child process: ')
errorClass('PasswordNotFound', 'Could not find password')

/**
 * Expose new Keychain Access
 */
module.exports = new KeychainAccess()
