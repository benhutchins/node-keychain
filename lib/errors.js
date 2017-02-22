var errors = {}

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
  errors[errorType] = ErrorClass
}

errorClass('UnsupportedPlatform', 'Expected darwin platform, got: ')
errorClass('NoAccountProvided', 'An account is required')
errorClass('NoServiceProvided', 'A service is required')
errorClass('NoPasswordProvided', 'A password is required')
errorClass('ServiceFailure', 'Keychain failed to start child process: ')
errorClass('PasswordNotFound', 'Could not find password')

module.exports = errors
