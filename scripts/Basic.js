const base32 = require('./base32')
const rot = require('./Caesar').rot
const crypto = require('crypto');
const urlencode = require('urlencode');
const htmlencode = require('htmlencode')
const quopri = require('quoted-printable')
const utf8 = require('utf8');
const bubble = require('bubble_babble')
const brainfuck = require('./brainfuck')


exports.hex2string = function (str) {
  if (str.length % 2) {
    str = '0' + str;
  } 
  return new Buffer(str, 'hex').toString(); 
}

exports.string2hex = function (str) {
  return new Buffer(str).toString('hex');
}

exports.number2string = function (str) {
  return exports.hex2string(parseInt(str).toString(16));
}

exports.string2number = function (str) {
  return parseInt(exports.string2hex(str), 16).toString();
}

exports.bin2string = function (str) {
  if (!str.length % 8) {
    var s = ''
    for (var i = 0; i < str.length; i += 8) {
      s += String.fromCharCode(parseInt(str.slice(i, i + 8), 2));
    }
    return s
  }else {
    console.log("The length is not a multiple of 8");
  }
}

exports.string2bin = function (str) {
  return str.split("").map(i => { return i.charCodeAt(0).toString('2').padStart(8, "0") }).join("");
}

exports.base64Encode = function (str) {
  return new Buffer(str,"ascii").toString('base64');
}

exports.base64Decode = function (str) {
  return new Buffer(str, 'base64').toString();
}

exports.base32Encode = function (str) {
  return base32.encode(str)
}

exports.base32Decode = function (str) {
  return base32.decode(str)
}

exports.base16Encode = function (str) {
  return exports.string2hex(str).toUpperCase()
}

exports.base16Decode = function (str) {
  if (/[^0-9A-F]/.test(str)) {
    throw new Error('Invalid base16 characters');
  }
  return exports.hex2string(str)
}

exports.baseDecode = function (str) {
  try {
    return exports.base16Decode(str)
  } catch (error) {
    try {
      return exports.base32Decode(str)
    } catch (error) {
      return exports.base64Decode(str)
    }
  }
}

exports.rot13 = function (str) {
  return rot(str, 13)
}

exports.md5Hash = function (str) {
  let hash = crypto.createHash('md5');
  return hash.update(str).digest('hex')
}

exports.sha512Hash = function (str) {
  let hash = crypto.createHash('sha512');
  return hash.update(str).digest('hex')
}

exports.urlEncode = function (str) {
  return urlencode(str)
}

exports.urlDecode = function (str) {
  return urlencode.decode(str)
}

exports.htmlEncode = function (str) {
  return htmlencode.htmlEncode(str)
}

exports.htmlDecode = function (str) {
  return htmlencode.htmlDecode(str)
}

exports.quopriEncode = function (str) {
  return quopri.encode(utf8.encode(str))
}

exports.quopriDecode = function (str) {
  return utf8.decode(quopri.decode(str))
}

exports.bubbleDecode = function(str) {
	return bubble.decode(str).toString()
}

exports.bubbleEncode = function(str) {
  return bubble.encode(str)
}

exports.brainfuckDecode = function (str) {
  return brainfuck.run(str)
}