const vscode = require('vscode')
const caesar = require('./scripts/Caesar')
const vigenere = require('./scripts/Vigenere')
const morse = require('xmorse')
const basic = require('./scripts/Basic')
const manip = require('./scripts/textManipulation')
const crypto = require('crypto')
const fs = require('fs')
const fence = require('./scripts/Fence')
const jssm4 = require('jssm4')

/**
 * 插件被激活时触发，所有代码总入口
 * @param {*} context 插件上下文
 */

//格式化
String.prototype.format = function () {
  var args = arguments
  return this.replace(/\{(\d+)\}/gm, (ms, p1) => {
    return typeof args[p1] == 'undefined' ? ms : args[p1]
  })
}

//显示信息与更新文本
function outputChannelShow(text) {
  outputChannel.show()
  outputChannel.appendLine(text)
}

function outputChannelUpdate(alg, before, after, update) {
  if (after) {
    //output
    outputChannelShow('------------------------------------')
    outputChannelShow('  ◆   ' + alg + ':')
    outputChannelShow('[ ⇐ ] ' + before)
    outputChannelShow('[ ⇒ ] ' + after)
    //update
    if (update) {
      editor.edit((editBuilder) => {
        editBuilder.replace(selection, after)
      })
      outputChannelShow('[ ✔ ] 文本已自动更新，按 Ctrl + Z 撤销')
    }
    outputChannelShow('------------------------------------')
  } else {
    vscode.window.showErrorMessage('转换失败！请检查文本类型或查看日志！')
  }
}

//凯撒
async function caesarCipher(text) {
  result = caesar.caesar(text)
  console.log(result)
  let choise = await vscode.window.showQuickPick(result, {
    placeHolder: '选择其中一种结果进行替换',
  })
  if (choise) {
    vscode.window.showInformationMessage(
      '选择了位移了' + result.indexOf(choise) + '位的结果',
    )
    outputChannelUpdate('caesarCipher', text, choise, true)
  }
}
//位移
async function characterOffset(text) {
  let value = await vscode.window.showInputBox({
    prompt: '输入最大的位移位数n和方向l或r，以逗号隔开',
    value: '50,l',
  })
  if (value) {
    let n = value.split(',')[0]
    let d = value.split(',')[1]
    result = caesar.shift(text, n, d)
    console.log(result)
    let choise = await vscode.window.showQuickPick(result, {
      placeHolder: '选择其中一种结果进行替换',
    })
    if (choise) {
      vscode.window.showInformationMessage(
        '选择了位移了' + result.indexOf(choise) + '位的结果',
      )
      outputChannelUpdate('characterOffset', text, choise, true)
    }
  }
}
//栅栏
async function fenceCipher(text, alg) {
  let result = []
  if (alg.includes('Encode')) {
    for (var i = 2; i < text.length; i++) {
      result.push(fence.encrypt(text, i))
    }
  } else {
    for (var i = 2; i < text.length; i++) {
      result.push(fence.decrypt(text, i))
    }
  }
  console.log(result)
  let choise = await vscode.window.showQuickPick(result, {
    placeHolder: '选择其中一种结果进行替换',
  })
  if (choise) {
    vscode.window.showInformationMessage(
      '选择了栏数为' + (result.indexOf(choise) + 2) + '的结果',
    )
    outputChannelUpdate('fenceCipher', text, choise, true)
  }
}

//维吉尼亚
async function vigenereCipher(text, alg) {
  let key = await vscode.window.showInputBox({
    placeHolder: '输入秘钥',
  })
  if (key) {
    if (alg.includes('Encode')) {
      var result = vigenere.Vigenere(text, key, true)
    } else {
      var result = vigenere.Vigenere(text, key, false)
    }
    outputChannelUpdate(alg, text, result, true)
  }
}

async function vigenereAutoDecode(text) {
  let minlen = 1 //从1开始猜测key的长度
  while (true) {
    let guessKey = new Promise((resolve) => {
      let result = vigenere.deVigenereAuto(text, false, minlen, 100) //默认key的长度未知
      resolve(result)
    })
    result = await guessKey
    outputChannelUpdate('vigenereAutoDecode', text, result[0], false)
    outputChannelShow('最有可能的key为：' + result[1])
    minlen = result[2] + 1 //如果没猜对，从猜出的秘钥长度+1之后继续猜
    let choise = await vscode.window.showInformationMessage(
      '请在输出日志中确认秘钥和明文是否猜测正确？',
      '是',
      '否',
    )
    if (choise != '否') {
      outputChannelUpdate('vigenereAutoDecode', text, result[0], true)
      break
    }
  }
}

function cryptoCipher(plainText, algorithm, key, iv, encoding = 'base64') {
  let cipher = crypto.createCipheriv(algorithm, key, iv)
  return cipher.update(plainText, 'utf8', encoding) + cipher.final(encoding)
}

function cryptoDecipher(cipher, algorithm, key, iv, encoding = 'base64') {
  let decipher = crypto.createDecipheriv(algorithm, key, iv)
  return decipher.update(cipher, encoding, 'utf8') + decipher.final('utf8')
}
let latestSymmetricCryptionKeyIv
//对称加密
async function symmetricCryption(text, alg) {
  let ciphers = crypto.getCiphers()
  ciphers.includes('sm4-ecb') || ciphers.push('sm4-ecb')
  let algorithm = await vscode.window.showQuickPick(ciphers, {
    placeHolder: '请选择要使用的对称加密算法',
  })
  if (!algorithm) return
  let value = await vscode.window.showInputBox({
    placeHolder: '请输入秘钥和初始向量(如有),并以英文“,”隔开',
    value: latestSymmetricCryptionKeyIv || '',
  })
  latestSymmetricCryptionKeyIv = value
  let key = value.split(',')[0] || ''
  let iv = value.split(',')[1] || ''
  outputChannelShow('Key: ' + key + ' IV: ' + iv)
  let result
  try {
    if (alg.includes('Encryption')) {
      result =
        algorithm === 'sm4-ecb'
          ? new jssm4(key).encryptData_ECB(text)
          : cryptoCipher(text, algorithm, key, iv)
    } else {
      result =
        algorithm === 'sm4-ecb'
          ? new jssm4(key).decryptData_ECB(text)
          : cryptoDecipher(text, algorithm, key, iv)
    }
  } catch (err) {
    outputChannelShow('[ ✘ ] ' + err)
  }
  outputChannelUpdate(alg + ' - ' + algorithm, text, result, true)
}

//RSA加密
function checkKey(keyfile, key) {
  let pri = [crypto.privateEncrypt, crypto.privateDecrypt]
  let pub = [crypto.publicEncrypt, crypto.publicDecrypt]
  if (key.includes('PRIVATE')) {
    outputChannelShow('选择了私钥文件: ' + keyfile)
    return pri
  } else if (key.includes('PUBLIC')) {
    outputChannelShow('选择了公钥文件: ' + keyfile)
    return pub
  } else {
    outputChannelShow('[ ✘ ] 秘钥格式似乎不对')
    outputChannelShow('私钥的开头和结尾分别为:')
    outputChannelShow('-----BEGIN RSA PRIVATE KEY-----')
    outputChannelShow('-----END RSA PRIVATE KEY-----')
    outputChannelShow('公钥的开头和结尾分别为:')
    outputChannelShow('-----BEGIN PUBLIC KEY-----')
    outputChannelShow('-----END PUBLIC KEY-----')
  }
}

async function rsaCryption(text, alg) {
  try {
    let file = await vscode.window.showOpenDialog({
      openLabel: '选择秘钥',
    })
    if (file) {
      let keyfile = file[0].fsPath
      let key = fs.readFileSync(keyfile).toString('utf-8')
      if (alg.includes('Encryption')) {
        crypt = checkKey(keyfile, key)[0]
        var result = crypt(key, new Buffer(text)).toString('base64')
      } else {
        crypt = checkKey(keyfile, key)[1]
        var result = crypt(key, new Buffer(text, 'base64')).toString('utf8')
      }
      outputChannelUpdate(alg, text, result, true)
    }
  } catch (err) {
    outputChannelShow(err)
  }
}

//摩斯
async function morseCoding(text, alg) {
  let value = await vscode.window.showInputBox({
    value: "{ space: '/', long: '-', short: '.' }",
    prompt: '请输入对应的间隔符、划、点的符号',
  })
  if (value) {
    let option = eval('(' + value + ')')
    if (alg.includes('Encode')) {
      var result = morse.encode(text, option)
    } else {
      var result = morse.decode(text, option)
    }
    outputChannelUpdate(alg, text, result, true)
  }
}

//十六进制计算器
async function calculator(text) {
  let value = await vscode.window.showInputBox({
    placeHolder: '输入要计算的公式，非十进制数以0x、0b、0o开头',
    value: text,
  })
  if (value) {
    try {
      let result = eval(value)
      let dec = parseFloat(result)
      let hex = '0x' + dec.toString(16)
      let oct = '0o' + dec.toString(8)
      let bin = '0b' + dec.toString(2)
      let str =
        /^[\x20-\x7e]+$/.test(basic.number2string(dec)) &&
        basic.number2string(dec)
      log = `dec: {0}
			hex: {1}
			bin: {2}
			oct: {3}`.format(dec, hex, bin, oct)
      if (str) {
        log += '\n			str: "{0}"'.format(str)
      }
      outputChannelUpdate('hexadecimalConverter', value, log, false)
    } catch (err) {
      vscode.window.showErrorMessage('输入非公式，将先转换成十六进制再计算')
      let hex = '0x' + basic.string2hex(value)
      calculator(hex)
    }
  }
}

//处理text/x-code-output兼容问题
//获取output channel的高亮语法
function getPatterns(file) {
  let content = fs.readFileSync(file, 'utf-8')
  let patterns = /<key>patterns<\/key>[\s|\S]*?<array>([\s|\S]*?)<\/array>/.exec(
    content,
  )[1]
  return patterns
}

//去除相关插件JSON文件里的"text/x-code-output"，以免冲突
function rmOutput(file) {
  let content = fs.readFileSync(file, 'utf-8')
  let New = content.replace('text/x-code-output', 'text/bak-x-code-output')
  fs.writeFileSync(file, New)
}

//获取定义了output channel语法的文件，并整合语法
function getLang() {
  let lang = ''
  const extension = vscode.extensions.all
  for (let e of extension) {
    try {
      let mimetypes = e.packageJSON.contributes.languages[0].mimetypes
      if (mimetypes.includes('text/x-code-output')) {
        let id = e.id
        if (id != 'fofolee.crypto-tools') {
          let extensionPath = e.extensionPath
          let grammarsPath = e.packageJSON.contributes.grammars[0].path.substr(
            1,
          )
          rmOutput(manip.convPath(extensionPath + '/package.json'))
          outputChannelShow('发现定义了output语法的冲突插件:\n' + extensionPath)
          file = manip.convPath(extensionPath + grammarsPath)
          console.log(file)
          lang +=
            '        <!-- ' +
            id +
            ' start -->' +
            getPatterns(file) +
            '<!-- ' +
            id +
            ' end -->\n'
        }
      }
    } catch (err) {}
  }
  return lang
}

outputChannel = vscode.window.createOutputChannel('crypto')

exports.activate = (context) => {
  // 注册命令
  context.subscriptions.push(
    vscode.commands.registerCommand('crypto.EncodeDecode', async () => {
      editor = vscode.window.activeTextEditor
      selection = editor.selection
      let text = editor.document.getText(selection).trim()
      let algorithm = await vscode.window.showQuickPick(
        [
          {
            label: 'Base64/32/16 Decode',
            detail: '自动进行base64/32/16解密',
            target: basic.baseDecode,
          },
          {
            label: 'Base64 Encode',
            detail: 'base64加密',
            target: basic.base64Encode,
          },
          {
            label: 'Base32 Encode',
            detail: 'base32加密',
            target: basic.base32Encode,
          },
          {
            label: 'Base16 Encode',
            detail: 'base16加密',
            target: basic.base16Encode,
          },
          {
            label: 'MD5',
            detail: 'MD5哈希算法',
            target: basic.md5Hash,
          },
          {
            label: 'SHA512',
            detail: 'SHA512哈希算法',
            target: basic.sha512Hash,
          },
          {
            label: 'Url Decode',
            detail: 'url加密',
            target: basic.urlDecode,
          },
          {
            label: 'Url Encode',
            detail: 'url解密',
            target: basic.urlEncode,
          },
          {
            label: 'Html Entities',
            detail: 'html加密',
            target: basic.htmlEncode,
          },
          {
            label: 'Html Entity Decode',
            detail: 'html解密',
            target: basic.htmlDecode,
          },
          {
            label: 'Morse Encode',
            detail: '摩斯密码加密',
            target: morseCoding,
          },
          {
            label: 'Morse Decode',
            detail: '摩斯密码解密',
            target: morseCoding,
          },
          {
            label: 'ROT13',
            detail: 'ROT13加密',
            target: basic.rot13,
          },
          {
            label: 'Quote-Printable Decode',
            detail: 'Quote-Printable解密',
            target: basic.quopriDecode,
          },
          {
            label: 'Quote-Printable Encode',
            detail: 'Quote-Printable加密',
            target: basic.quopriEncode,
          },
          {
            label: 'Bubble Babble Decode',
            detail: 'Bubble Babble 解密',
            target: basic.bubbleDecode,
          },
          {
            label: 'Bubble Babble Encode',
            detail: 'Bubble Babble 加密',
            target: basic.bubbleEncode,
          },
          {
            label: 'Brainfuck Decode',
            detail: 'Brainfuck 解密',
            target: basic.brainfuckDecode,
          },
          {
            label: 'Number To String',
            detail: '整型转字符',
            target: basic.number2string,
          },
          {
            label: 'String To Number',
            detail: '字符转整型',
            target: basic.string2number,
          },
          {
            label: 'String To Hex',
            detail: '字符转十六进制',
            target: basic.string2hex,
          },
          {
            label: 'Hex To String',
            detail: '十六进制转字符',
            target: basic.hex2string,
          },
          {
            label: 'String To Bin',
            detail: '字符转二进制',
            target: basic.string2bin,
          },
          {
            label: 'Bin To String',
            detail: '二进制转字符',
            target: basic.bin2string,
          },
        ],
        {
          placeHolder: '选择一种算法',
        },
      )
      if (algorithm) {
        let result = algorithm.target(text)
        outputChannelUpdate(algorithm.label, text, result, true)
      }
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('crypto.EncryptDecrypt', async () => {
      editor = vscode.window.activeTextEditor
      selection = editor.selection
      let text = editor.document.getText(selection).trim()
      let algorithm = await vscode.window.showQuickPick(
        [
          {
            label: 'Symmetric Decryption',
            detail: '对称密码解密算法，密文格式为Base64',
            target: symmetricCryption,
          },
          {
            label: 'Symmetric Encryption',
            detail: '对称密码加密算法，密文格式为Base64',
            target: symmetricCryption,
          },
          {
            label: 'RSA Decryption',
            detail: '使用公钥或私钥文件进行RSA解密',
            target: rsaCryption,
          },
          {
            label: 'RSA Encryption',
            detail: '使用公钥或私钥文件进行RSA加密',
            target: rsaCryption,
          },
          {
            label: 'Caesar Cipher',
            detail: '凯撒密码',
            target: caesarCipher,
          },
          {
            label: 'Character Offset',
            detail: '字符位移',
            target: characterOffset,
          },
          {
            label: 'Fence Decode',
            detail: '栅栏密码解密',
            target: fenceCipher,
          },
          {
            label: 'Fence Encode',
            detail: '栅栏密码加密',
            target: fenceCipher,
          },
          {
            label: 'Vigenere Encode',
            detail: '维基尼亚加密',
            target: vigenereCipher,
          },
          {
            label: 'Vigenere Decode',
            detail: '维基尼亚解密',
            target: vigenereCipher,
          },
          {
            label: 'Vigenere Decode with No Key',
            detail: '维基尼亚无秘钥解密',
            target: vigenereAutoDecode,
          },
        ],
        {
          placeHolder: '选择一种算法',
        },
      )
      if (algorithm) {
        algorithm.target(text, algorithm.label)
      }
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('crypto.textManipulation', async () => {
      editor = vscode.window.activeTextEditor
      selection = editor.selection
      let text = editor.document.getText(selection).trim()
      let algorithm = await vscode.window.showQuickPick(
        [
          {
            label: 'Reverse String',
            detail: '字符串逆转',
            target: manip.reverseString,
          },
          {
            label: 'Upper Case',
            detail: '全部大写',
            target: manip.upperString,
          },
          {
            label: 'Lower Case',
            detail: '全部小写',
            target: manip.lowerString,
          },
          {
            label: 'Strip String',
            detail: '去除左右空格、换行',
            target: manip.stripString,
          },
          {
            label: 'Space To None',
            detail: '去除所有空格',
            target: manip.space2None,
          },
          {
            label: 'Space To Line',
            detail: '空格转换行',
            target: manip.space2Line,
          },
          {
            label: 'Convert Path',
            detail: '\\和/互转',
            target: manip.convPath,
          },
          {
            label: 'Title Case',
            detail: '所有词首字母大写',
            target: manip.titleCase,
          },
          {
            label: 'String Lenght',
            detail: '获取文本长度',
            target: manip.stringLen,
          },
          {
            label: 'Add Quot By Comma',
            detail: '为每个以逗号分隔的词加上双引号',
            target: manip.addQuotByComma,
          },
          {
            label: 'Add Quot By Space',
            detail: '为每个以空格分隔的词加上双引号',
            target: manip.addQuotBySpace,
          },
        ],
        {
          placeHolder: '选择一种处理方案',
        },
      )
      if (algorithm) {
        let result = algorithm.target(text)
        if (algorithm.label != 'String Lenght') {
          outputChannelUpdate(algorithm.label, text, result, true)
        } else {
          outputChannelUpdate(algorithm.label, text, result, false)
          vscode.window.showInformationMessage('长度为：' + result)
        }
      }
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('crypto.hexadecimalCalculator', () => {
      calculator('')
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('crypto.outputColorPatch', async () => {
      let choise = await vscode.window.showInformationMessage(
        '如果安装本插件后，本插件的输出没有高亮，或者造成其他插件的输出没有高亮，则是因为和其他一些插件的输出语法产生了冲突，是否尝试自动修复这些冲突？',
        '是',
        '否',
      )
      if (choise == '是') {
        outputChannelShow('正在尝试寻找问题···')
        let langFile = __dirname + '/syntaxes/crypto-tools-output.tmLanguage'
        let file = fs.readFileSync(langFile, 'utf-8')
        let lang = getLang()
        let New = file.replace('        </array>', lang + '        </array>')
        console.log(New)
        fs.writeFileSync(langFile, New)
        if (lang) {
          outputChannelShow('语法文件已整合，请重启编辑器！')
        } else {
          outputChannelShow('未发现冲突的文件！')
        }
      }
    }),
  )
}
