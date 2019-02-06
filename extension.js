const vscode = require('vscode');
const system = require('child_process').exec;
const caesar = require('./scripts/Caesar');
const vigenere = require('./scripts/Vigenere');
const morse = require('xmorse');
const basic = require('./scripts/Basic');
const manip = require('./scripts/textManipulation');
const crypto = require('crypto');
const fs = require('fs')
const fence = require('./scripts/Fence')

/**
 * 插件被激活时触发，所有代码总入口
 * @param {*} context 插件上下文
 */

//格式化
String.prototype.format = function () {
	var args = arguments;
	return this.replace(/\{(\d+)\}/gm, (ms, p1) => {
		return typeof (args[p1]) == 'undefined' ? ms : args[p1]
	});
}

//显示信息与更新文本
function print(text) {
	outputChannel.show();
	return outputChannel.appendLine(text)
}

function showUpdate(alg, before, after, update) {
	if (after) {
		//output
		print("------------------------------------")
		print("  ◆   " + alg + ":");
		print('[ ⇐ ] ' + before);
		print('[ ⇒ ] ' + after);
		//update
		if (update) {
			editor.edit(editBuilder => {
				editBuilder.replace(selection, after);
			});
			print('[ ✔ ] 文本已自动更新，按 Ctrl + Z 撤销');
		}
		print("------------------------------------");
	} else {
		vscode.window.showErrorMessage("转换失败！请检查文本类型或查看日志！")
	}
}


//破解hash
function crackHash(text) {
	vscode.window.showInformationMessage("请确保网络和Python环境正常，正在破解中···");
	system('python {0}/scripts/HashBuster.py -s {1}'.format(__dirname, text), (err, stdout) => {
		if (stdout.indexOf("[-]") == -1) {
			let hashtype = stdout.split('\n')[0].split('[!]')[1].trim()
			let plaintext = stdout.split('\n')[1].trim()
			vscode.window.showInformationMessage(hashtype);
			showUpdate("hashBuster", text, plaintext, true);
		} else {
			let result = stdout.split('[-]');
			let errorMessage = result[1].trim();
			vscode.window.showErrorMessage(errorMessage);
			if (result[0]) {
				let hashtype = result[0].split('[!]')[1].trim();
				vscode.window.showInformationMessage(hashtype);
			}
		}
		if (err) {
			print('[ ✘ ] ' + err);
		}
	})
}

function crackHashInFile() {
	let file = vscode.window.activeTextEditor.document.fileName;
	vscode.window.showInformationMessage("请确保网络和Python环境正常，正在破解中···");
	system('python {0}/scripts/HashBuster.py -f {1}'.format(__dirname, file), (err, stdout) => {
		print("------------------------------------");
		print(stdout)
		print("------------------------------------");
		if (err) {
			print('[ ✘ ] ' + err);
		}
	})
}

//凯撒
async function Caesar(text) {
	result = caesar.caesar(text);
	console.log(result);
	let choise = await vscode.window.showQuickPick(result, {
		placeHolder: '选择其中一种结果进行替换'
	});
	if (choise) {
		vscode.window.showInformationMessage("选择了位移了" + result.indexOf(choise) + "位的结果");
		showUpdate("Caesar", text, choise, true);
	}
}
//位移
async function Shift(text) {
	let value = await vscode.window.showInputBox({
		prompt: '输入最大的位移位数n和方向l或r，以逗号隔开',
		value: "50,l"
	});
	if (value) {
		let n = value.split(',')[0];
		let d = value.split(',')[1];
		result = caesar.shift(text, n, d);
		console.log(result);
		let choise = await vscode.window.showQuickPick(result, {
			placeHolder: '选择其中一种结果进行替换'
		});
		if (choise) {
			vscode.window.showInformationMessage("选择了位移了" + result.indexOf(choise) + "位的结果");
			showUpdate("Shift", text, choise, true);
		}
	}
}
//栅栏
async function Fence(text, alg) {
	let result = []
	if (alg.includes("Encode")) {
		for (var i = 2; i < text.length; i++) {
			result.push(fence.encrypt(text, i))
		}
	} else {
		for (var i = 2; i < text.length; i++) {
			result.push(fence.decrypt(text, i))
		}
	}
	console.log(result);
	let choise = await vscode.window.showQuickPick(result, {
		placeHolder: '选择其中一种结果进行替换'
	});
	if (choise) {
		vscode.window.showInformationMessage("选择了栏数为" + (result.indexOf(choise) + 2) + "的结果");
		showUpdate("Shift", text, choise, true);
	}
}

//维吉尼亚
async function Vigenere(text, alg) {
	let key = await vscode.window.showInputBox({
		placeHolder: '输入秘钥'
	});
	if (key) {
		if (alg.includes("Encode")) {
			var result = vigenere.Vigenere(text, key, true);
		} else {
			var result = vigenere.Vigenere(text, key, false);
		}
		showUpdate(alg, text, result, true);
	}
}


async function vigenereAutoDecode(text) {
	let minlen = 1; //从1开始猜测key的长度
	while (true) {
		let guessKey = new Promise((resolve) => {
			let result = vigenere.deVigenereAuto(text, false, minlen, 100); //默认key的长度未知
			resolve(result);
		});
		result = await guessKey;
		showUpdate("vigenereAutoDecode", text, result[0], false);
		print("最有可能的key为：" + result[1]);
		minlen = result[2] + 1; //如果没猜对，从猜出的秘钥长度+1之后继续猜
		let choise = await vscode.window.showInformationMessage("请在输出日志中确认秘钥和明文是否猜测正确？", "是", "否");
		if (choise != "否") {
			showUpdate("vigenereAutoDecode", text, result[0], true);
			break;
		}
	}
}

//对称加密
async function symmetricCryption(text, alg) {
	let algorithm = await vscode.window.showQuickPick(crypto.getCiphers(), {
		placeHolder: "请选择要使用的对称加密算法"
	})
	if (algorithm) {
		let value = await vscode.window.showInputBox({
			placeHolder: '请输入秘钥和初始向量,以逗号隔开,可不填',
		});
		let key = value.split(',')[0] || "";
		let iv = value.split(',')[1] || "";
		print("Key: " + key + " IV: " + iv)
		try {
			if (alg.includes("Encryption")) {
				if (iv) {
					var cipher = crypto.createCipheriv(algorithm, key, iv);
				} else {
					var cipher = crypto.createCipher(algorithm, key);
				}
				var result = cipher.update(text, 'utf8', 'base64');
				result += cipher.final('base64');
			} else {
				if (iv) {
					var decipher = crypto.createDecipheriv(algorithm, key);
				} else {
					var decipher = crypto.createDecipher(algorithm, key);
				}
				var result = decipher.update(text, 'base64', 'utf8');
				result += decipher.final('utf8');
			}
		} catch (err) {
			print('[ ✘ ] ' + err)
		}
		showUpdate(alg + " - " + algorithm, text, result, true);
	}
}

//RSA加密
function checkKey(keyfile, key) {
	let pri = [crypto.privateEncrypt, crypto.privateDecrypt];
	let pub = [crypto.publicEncrypt, crypto.publicDecrypt]
	if (key.includes("PRIVATE")) {
		print("选择了私钥文件: " + keyfile)
		return pri
	} else if (key.includes("PUBLIC")) {
		print("选择了公钥文件: " + keyfile)
		return pub
	} else {
		print("[ ✘ ] 秘钥格式似乎不对");
		print("私钥的开头和结尾分别为:");
		print("-----BEGIN RSA PRIVATE KEY-----");
		print("-----END RSA PRIVATE KEY-----");
		print("公钥的开头和结尾分别为:");
		print("-----BEGIN PUBLIC KEY-----");
		print("-----END PUBLIC KEY-----")
	}
}

async function rsaCryption(text, alg) {
	try {
		let file = await vscode.window.showOpenDialog({
			openLabel: '选择秘钥'
		});
		if (file) {
			let keyfile = file[0].fsPath;
			let key = fs.readFileSync(keyfile).toString('utf-8')
			if (alg.includes("Encryption")) {
				crypt = checkKey(keyfile, key)[0];
				var result = crypt(key, new Buffer(text)).toString('base64');
			} else {
				crypt = checkKey(keyfile, key)[1];
				var result = crypt(key, new Buffer(text, 'base64')).toString("utf8");
			}
			showUpdate(alg, text, result, true);
		}
	} catch (err) {
		print(err)
	}
}

//摩斯
async function Morse(text, alg) {
	let value = await vscode.window.showInputBox({
		value: "{ space: '/', long: '-', short: '.' }",
		prompt: "请输入对应的间隔符、划、点的符号"
	});
	if (value) {
		let option = eval('(' + value + ')');
		if (alg.includes("Encode")) {
			var result = morse.encode(text, option);
		} else {
			var result = morse.decode(text, option);
		}
		showUpdate(alg, text, result, true)
	};
}

//十六进制计算器
async function calculator(text) {
	let value = await vscode.window.showInputBox({
		placeHolder: '输入要计算的公式，非十进制数以0x、0b、0o开头',
		value:text
	});
	if (value) {
		try {
			let result = eval(value)
			let dec = parseFloat(result);
			let hex = "0x" + dec.toString(16);
			let oct = "0o" + dec.toString(8);
			let bin = "0b" + dec.toString(2);
			let str = /^[\x20-\x7e]+$/.test(basic.number2string(dec)) && basic.number2string(dec)
			log = `dec: {0}
			hex: {1}
			bin: {2}
			oct: {3}`.format(dec, hex, bin, oct);
			if (str) {
				log += '\n			str: "{0}"'.format(str)
			}
			showUpdate("hexadecimalConverter", value, log, false);
		}
		catch (err) {
			vscode.window.showErrorMessage("输入非公式，将先转换成十六进制再计算")
			let hex = '0x' + basic.string2hex(value);
			calculator(hex);
			}
	}
}

outputChannel = vscode.window.createOutputChannel('Crypto');
editor = vscode.window.activeTextEditor;

exports.activate = context => {
	// 注册命令
	context.subscriptions.push(vscode.commands.registerCommand('crypto.EncodeDecode', async () => {
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "ROT13",
				detail: "ROT13加密",
				target: basic.rot13
			},
			{
				label: "Base64/32/16 Decode",
				detail: "自动进行base64/32/16解密",
				target: basic.baseDecode
			},
			{
				label: "Base64 Encode",
				detail: "base64加密",
				target: basic.base64Encode
			},
			{
				label: "Base32 Encode",
				detail: "base32加密",
				target: basic.base32Encode
			},
			{
				label: "Base16 Encode",
				detail: "base16加密",
				target: basic.base16Encode
			},
			{
				label: "MD5",
				detail: "MD5哈希算法",
				target: basic.md5Hash
			},
			{
				label: "SHA512",
				detail: "SHA512哈希算法",
				target: basic.sha512Hash
			},
			{
				label: "Url Decode",
				detail: "url加密",
				target: basic.urlDecode
			},
			{
				label: "Url Encode",
				detail: "url解密",
				target: basic.urlEncode
			},
			{
				label: "Html Entities",
				detail: "html加密",
				target: basic.htmlEncode
			},
			{
				label: "Html Entity Decode",
				detail: "html解密",
				target: basic.htmlDecode
			},
			{
				label: "Quote-Printable Decode",
				detail: "Quote-Printable解密",
				target: basic.quopriDecode
			},
			{
				label: "Quote-Printable Encode",
				detail: "Quote-Printable加密",
				target: basic.quopriEncode
			},
			{
				label: "Bubble Babble Decode",
				detail: "Bubble Babble 解密",
				target: basic.bubbleDecode
			},
			{
				label: "Bubble Babble Encode",
				detail: "Bubble Babble 加密",
				target: basic.bubbleEncode
			},
			{
				label: "Brainfuck Decode",
				detail: "Brainfuck 解密",
				target: basic.brainfuckDecode
			},
			{
				label: "Number To String",
				detail: "整型转字符",
				target: basic.number2string
			},
			{
				label: "String To Number",
				detail: "字符转整型",
				target: basic.string2number
			},
			{
				label: "String To Hex",
				detail: "字符转十六进制",
				target: basic.string2hex
			},
			{
				label: "Hex To String",
				detail: "十六进制转字符",
				target: basic.hex2string
			},
			{
				label: "String To Bin",
				detail: "字符转二进制",
				target: basic.string2bin
			},
			{
				label: "Bin To String",
				detail: "二进制转字符",
				target: basic.bin2string
			}
		], {
			placeHolder: '选择一种算法'
		});
		if (algorithm) {
			let result = algorithm.target(text);
			showUpdate(algorithm.label, text, result, true);
		}
	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.EncryptDecrypt', async () => {
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "Crack Hash",
				detail: "破解选中的哈希值",
				target: crackHash
			},
			{
				label: "Crack Hashes In File",
				detail: "破解当前文件中所有的哈希值",
				target: crackHashInFile
			},
			{
				label: "Symmetric Decryption",
				detail: "对称密码解密算法，密文格式为Base64",
				target: symmetricCryption
			},
			{
				label: "Symmetric Encryption",
				detail: "对称密码加密算法，密文格式为Base64",
				target: symmetricCryption
			},
			{
				label: "RSA Decryption",
				detail: "使用公钥或私钥文件进行RSA解密",
				target: rsaCryption
			},
			{
				label: "RSA Encryption",
				detail: "使用公钥或私钥文件进行RSA加密",
				target: rsaCryption
			},
			{
				label: "Caesar Cipher",
				detail: "凯撒密码",
				target: Caesar
			},
			{
				label: "Character Offset",
				detail: "字符位移",
				target: Shift
			},
			{
				label: "Fence Decode",
				detail: "栅栏密码解密",
				target: Fence
			},
			{
				label: "Fence Encode",
				detail: "栅栏密码加密",
				target: Fence
			},
			{
				label: "Vigenere Encode",
				detail: "维基尼亚加密",
				target: Vigenere
			},
			{
				label: "Vigenere Decode",
				detail: "维基尼亚解密",
				target: Vigenere
			},
			{
				label: "Vigenere Decode with No Key",
				detail: "维基尼亚无秘钥解密",
				target: vigenereAutoDecode
			},
			{
				label: "Morse Encode",
				detail: "摩斯密码加密",
				target: Morse
			},
			{
				label: "Morse Decode",
				detail: "摩斯密码解密",
				target: Morse
			}
		], {
			placeHolder: '选择一种算法'
		});
		if (algorithm) {
			algorithm.target(text, algorithm.label);
		}

	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.textManipulation', async () => {
		selection = editor.selection;
		let text = editor.document.getText(selection).trim();
		let algorithm = await vscode.window.showQuickPick([{
				label: "Reverse String",
				detail: "字符串逆转",
				target: manip.reverseString
			},
			{
				label: "Upper Case",
				detail: "全部大写",
				target: manip.upperString
			},
			{
				label: "Lower Case",
				detail: "全部小写",
				target: manip.lowerString
			},
			{
				label: "Strip String",
				detail: "去除左右空格、换行",
				target: manip.stripString
			},
			{
				label: "Space To None",
				detail: "去除所有空格",
				target: manip.space2None
			},
			{
				label: "Space To Line",
				detail: "空格转换行",
				target: manip.space2Line
			},
			{
				label: "Convert Path",
				detail: "\\和/互转",
				target: manip.convPath
			},
			{
				label: "Title Case",
				detail: "所有词首字母大写",
				target: manip.titleCase
			},
			{
				label: "String Lenght",
				detail: "获取文本长度",
				target: manip.stringLen
			},
			{
				label: "Add Quot By Comma",
				detail: "为每个以逗号分隔的词加上双引号",
				target: manip.addQuotByComma
			},
			{
				label: "Add Quot By Space",
				detail: "为每个以空格分隔的词加上双引号",
				target: manip.addQuotBySpace
			}
		], {
			placeHolder: '选择一种处理方案'
		});
		if (algorithm) {
			let result = algorithm.target(text);
			if (algorithm.label != "String Lenght") {
				showUpdate(algorithm.label, text, result, true);
			} else {
				showUpdate(algorithm.label, text, result, false);
				vscode.window.showInformationMessage("长度为：" + result);
			}
		}

	}));

	context.subscriptions.push(vscode.commands.registerCommand('crypto.hexadecimalCalculator', () => {
		calculator("");

	}));

};