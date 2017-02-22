var ref = require('ref')
var ffi = require('ffi')
var errors = require('../errors')

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

module.exports = {
  get: function (opts, fn) {
    var keychainRef = ref.alloc(SecKeychainRef)
    var exitStatus = security.SecKeychainCopyDefault(keychainRef)

    if (exitStatus !== 0) {
      return fn(new errors.ServiceFailureError())
    }

    var keychainDeref = keychainRef.deref()
    var passwordLength = ref.alloc(ref.types.uint32)
    var passwordData = ref.alloc('string')

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
      return fn(new errors.PasswordNotFoundError())
    }

    var passwordDeref = passwordData.deref()
    var password = passwordDeref.toString('utf8')

    fn(null, password)
  },

  set: function (opts, fn) {
    var keychainRef = ref.alloc(SecKeychainRef)
    var exitStatus = security.SecKeychainCopyDefault(keychainRef)

    if (exitStatus !== 0) {
      return fn(new errors.ServiceFailureError())
    }

    var keychainDeref = keychainRef.deref()

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
      fn(new errors.ServiceFailureError(null, exitStatus))
    } else {
      fn(null)
    }
  },

  del: function (opts, fn) {
    var keychainRef = ref.alloc(SecKeychainRef)
    var exitStatus = security.SecKeychainCopyDefault(keychainRef)

    if (exitStatus !== 0) {
      return fn(new errors.ServiceFailureError())
    }

    var keychainDeref = keychainRef.deref()
    var itemRef = ref.alloc(SecKeychainItemRef)

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

    if (exitStatus === -25300) {
      return fn(new errors.PasswordNotFoundError())
    } else if (exitStatus !== 0) {
      return fn(new errors.ServiceFailureError(null, exitStatus))
    }

    exitStatus = security.SecKeychainItemDelete(itemRef.deref())

    if (exitStatus !== 0) {
      return fn(new errors.ServiceFailureError(null, exitStatus))
    }

    fn(null)
  }
}
