exports.upperString = function(text) {
	return text.toUpperCase();
}
exports.lowerString = function(text) {
	return text.toLowerCase();
}
exports.stripString = function(text) {
	return text.trim();
}
exports.reverseString = function(text) {
	return text.split("").reverse().join("");
}
exports.space2None = function(text) {
	return text.replace(/\s/g, "");
}
exports.space2Line = function(text) {
	return text.replace(/\s/g, "\n");
}
exports.convPath = function (text) {
	if (text.includes("/")) {
		return text.replace(/\//g, "\\");	
	} else {
		return text.replace(/\\/g, "/");	
	}
}
exports.titleCase = function(text) {
	return text.toLowerCase().replace(/( |^)[a-z]/g, (L) => L.toUpperCase()); 
}
exports.addQuotByComma = function(text) {
	return text.split(',').map(i => { return '"' + i.trim() + '"' }).join(", ");
}
exports.addQuotBySpace = function(text) {
	return text.split(' ').map(i => { return '"' + i.trim() + '"' }).join(" ");
}
exports.stringLen = function(text) {
	return text.length;
}