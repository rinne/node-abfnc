const ArbitraryBlockFeistelHashCipher = require('./abfnc.js');

/*
['secret', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.', 'foo'].forEach(function(k) {
	['md5','sha1','sha256','sha512'].forEach(function(h) {
		var x = new ArbitraryBlockFeistelHashCipher(k, h);
		console.log(a.join(''));
		var b = x.encrypt(a);
		console.log(b.join(''));
		var c = x.decrypt(b);
		console.log(c.join(''));
	});
});
*/

var bits = 15;
var x = new ArbitraryBlockFeistelHashCipher('foo', 'md5', 24, bits);
var i;
const KeepTime = require('keeptime');
var kt = new KeepTime();
for (i = 0; i < Math.min(100, Math.pow(2,bits)); i++) {
	var a, b, c;
	a = i;
	kt.reset();
	kt.start();
	b = x.encryptNum(a);
	kt.stop();
	//console.log('encrypt took ' + kt.get() + ' seconds');
	kt.reset();
	kt.start();
	c = x.decryptNum(b);
	kt.stop();
	//console.log('decrypt took ' + kt.get() + ' seconds');
	console.log(a.toString() + ' -> ' + b.toString() + ' -> ' + c.toString());
}
