const ArbitraryBlockFeistelHashCipher = require('../abfnc.js');

['md5','sha1','sha256','sha512'].forEach(function(hash) {
	[10, 20, 30, 40, 100, 300].forEach(function(bl) {
		var x = new ArbitraryBlockFeistelHashCipher('key', hash, 24, bl);
		[0, 1, ('1' + ('0').repeat(bl / 4))].forEach(function(p) {
			var c, v;
			c = x.encryptNum(p);
			v = x.decryptNum(c);
			if (v != p) {
				console.log('mismatch!');
				process.exit(1);
			}
			// console.log(p);
			// console.log(c);
		});
	});
});
process.exit(0);

// Better add well known test vectors here too.
