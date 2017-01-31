const ArbitraryBlockFeistelHashCipher = require('./abfnc.js');

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
