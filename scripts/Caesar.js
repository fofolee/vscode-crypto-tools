function caesar(s) {
  var result = new Array();
  for (var j = 0; j < 26; j++) {
    var z = rot(s, j)
    result[j] = z;
  }
  return result
}

function rot(s, n) {
  var z = '';
  var w;
  for (var i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) <= 90 && s.charCodeAt(i) >= 65) {
      w = (s.charCodeAt(i) + n - 65) % 26;
      w = String.fromCharCode(w + 65);
    } else if (s.charCodeAt(i) <= 122 && s.charCodeAt(i) >= 97) {
      w = (s.charCodeAt(i) + n - 97) % 26;
      w = String.fromCharCode(w + 97);
    } else {
      w = s[i];
    }
    z = z + w;
  }
  return z
}



function shift(s, max, d) {
  var result = new Array();
  for (var n = 0; n <= max; n++) {
    var z = ''
    for (var i = 0; i < s.length; i++) {
      if (d == 'r') {
        z += String.fromCharCode(s.charCodeAt(i) + n)
      } else {
        z += String.fromCharCode(s.charCodeAt(i) - n)
      }
    }
    result[n] = z;
  }
  return result
}

exports.rot = rot
exports.shift = shift
exports.caesar = caesar