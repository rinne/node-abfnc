'use strict';

/*
 *  ABFNC
 *
 *  This is an implementation of arbitrary block size feistel network
 *  encryption using user selectable cryptographic hash functions as
 *  source of pseudo randomness in round functions.
 *
 *  This Javascript implementation is functionally identical to PHP
 *  implementation that is distributed alongside with this one.
 *
 *  See README.md
 *
 *  Copyright (C) 2009-2016 Timo J. Rinne <tri@iki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

const crypto = require('crypto');
const bignum = require('bignum');

function validArr(arr) {
	if (! Array.isArray(arr)) {
		return false;
	}
	return (! arr.some(function(x) {
		return (! ((x === 0) || (x === 1)));
	}));
}

function i2a(n, bits) {
	var i, rv = [];
	if (! (Number.isSafeInteger(bits) && (bits > 0))) {
		return undefined;
	}
	if (Number.isSafeInteger(n)) {
		for (i = 0; i < bits; i++) {
			var m = n % 2;
			rv.unshift(m);
			if (n > 0) {
				n = (n - m) / 2;
			}
		}
		if (n > 0) {
			return undefined;
		}
	} else if ((typeof(n) === 'string') && n.match(/^(0|[1-9][0-9]*)$/)) {
		var zero = bignum('0'), two = bignum('2');
		for (i = 0, n = bignum(n); i < bits; i++) {
			var m = n.mod(two);
			rv.unshift(m.eq(zero) ? 0 : 1);
			if (n.gt(zero)) {
				n = n.sub(m).div(two);
			}
		}
		if (n.gt(zero)) {
			return undefined;
		}
	} else {
		return undefined;
	}
	return rv;
}

function a2i(arr) {
	if (! (Array.isArray(arr) && (arr.length > 0))) {
		return undefined;
	}
	var rv = 0;
	if (arr.some(function(x) {
		if (! ((x === 0) || (x === 1))) {
			return true;
		}
		if (Number.isSafeInteger(rv)) {
			var n = rv * 2 + x;
			if (Number.isSafeInteger(n)) {
				rv = n;
				return false;
			}
			rv = bignum(rv);
		}
		rv = rv.mul(2).add(x);
		return false;
	})) {
		return undefined;
	}
	return (typeof(rv) === 'number' ? rv : rv.toString());
}

function b2a(buf) {
	if (! (Buffer.isBuffer(buf) && (buf.length >= 4))) {
		return undefined;
	}
	var bits = buf.readUInt32BE(0);
	if ((Math.ceil(bits / 8) + 4) != buf.length) {
		return undefined;
	}
	var i, rv = [];
	for (i = 0; i < ((buf.length - 4) * 8); i++) {
		if (i < bits) {
			rv.push((buf[(i >> 3) + 4] >> (7 - (i & 7))) & 1);
		} else {
			if ((buf[(i >> 3) + 4] >> (7 - (i & 7))) & 1) {
				return undefined;
			}
		}
	}
	return rv;
}

function a2b(arr) {
	if (! (Array.isArray(arr))) {
		return undefined;
	}
	var i, rv = Buffer.alloc(Math.ceil(arr.length / 8) + 4);
	rv.writeUInt32BE(arr.length, 0);
	for (i = 0; i < arr.length; i++) {
		if (arr[i] === 1) {
			rv[(i >> 3) + 4] |= (1 << (7 - (i & 7)));
		} else if (arr[i] !== 0) {
			return undefined;
		}
	}
	return rv;
}

function s2b(str) {
	if (typeof(str) === 'string') {
		str = Buffer.from(str, 'utf8');
	} else if (! Buffer.isBuffer(str)) {
		return undefined;
	}
	return Buffer.concat([ uint2b(str.length << 3), str ]);
}

function s2a(str) {
	return b2a(s2b(str));
}

function uint2b(n) {
	if (! Number.isSafeInteger(n) && (n >= 0) && (n <= 0xffffffff)) {
		return undefined;
	}
	var rv = Buffer.alloc(4);
	rv.writeUInt32BE(n, 0);
	return rv;
}

function axor(a, b) {
	if (! (Array.isArray(a) && Array.isArray(b) && (a.length == b.length))) {
		return undefined;
	}
	var i, rv = [];
	for (i = 0; i < a.length; i++) {
		if (((a[i] !== 0) && (a[i] !== 1)) || ((b[i] !== 0) && (b[i] !== 1))) {
			return undefined;
		}
		rv.push(a[i] ^ b[i]);
	}
	return rv;
}

var ArbitraryBlockFeistelHashCipher = function(key,
											   hashAlgorithm,
											   rounds,
											   blockLengthBits,
											   leftHalfBlockLengthBits) {
	if (typeof(key) === 'string') {
		key = s2b(key);
	} else if (Buffer.isBuffer(key) && (b2a(key) !== undefined)) {
		key = key.slice(0);
	} else if (validArr(key)) {
		key = a2b(key);
	} else {
		throw new Error('Bad key');
	}
	if ((hashAlgorithm === undefined) || (hashAlgorithm === null)) {
		hashAlgorithm = 'sha512';
	} else if (! ((typeof(hashAlgorithm) === 'string') &&
				  (crypto.getHashes().indexOf(hashAlgorithm) >= 0))) {
		throw new Error('Bad hash algorithm');
	}
	if ((rounds === undefined) || (rounds === null)) {
		rounds = 24;
	} else if (! (Number.isSafeInteger(rounds) && (rounds > 5))) {
		throw new Error('Bad number of rounds');
	}
	if ((blockLengthBits === undefined) || (blockLengthBits === null)) {
		blockLengthBits = undefined;
		if ((leftHalfBlockLengthBits === undefined) || (leftHalfBlockLengthBits === null)) {
			leftHalfBlockLengthBits = undefined;
		} else {
			throw new Error('Explicit half block size with undefined block size');
		}
	} else if (Number.isSafeInteger(blockLengthBits) && (blockLengthBits >= 2)) {
		if ((leftHalfBlockLengthBits === undefined) || (leftHalfBlockLengthBits === null)) {
			leftHalfBlockLengthBits = blockLengthBits - (blockLengthBits >> 1);
		} else if (! (Number.isSafeInteger(leftHalfBlockLengthBits) &&
					  (leftHalfBlockLengthBits > 0) &&
					  (leftHalfBlockLengthBits < blockLengthBits))) {
			throw new Error('Bad half block size');
		}
	} else {
		throw new Error('Bad block size');
	}
	var skh = function(d, bits) {
		if (Array.isArray(d)) {
			d = a2b(d);
		} else if (typeof(d) === 'string') {
			d = s2b(d);
		}
		if (! Buffer.isBuffer(d)) {
			throw new Error('Bad input data');
		}
		if (! (Number.isSafeInteger(bits) && (bits > 0))) {
			throw new Error('Bad hash length');
		}
		var h, i, p, buf, b = Buffer.concat([ s2b(hashAlgorithm), uint2b(bits) ]);
		for (i = 0, p = Buffer.alloc(0), buf = Buffer.alloc(0); (buf.length << 3) < bits; i++) {
			try {
				h = crypto.createHash(hashAlgorithm);
			} catch(e) {
				h = undefined;
			}
			if (h === undefined) {
				throw new Error('Unable to create hash context');
			}
			h.update(b);
			h.update(d);
			if (i > 0) {
				h.update(uint2b(i));
				h.update(p);
			}
			p = h.digest();
			buf = Buffer.concat([ buf, p ]);
		}
		buf = buf.slice(0, Math.ceil(bits / 8));
		switch ((8 - (bits % 8)) % 8) {
		case 1:
			buf[buf.length - 1] &= 0xfe;
			break;
		case 2:
			buf[buf.length - 1] &= 0xfc;
			break;
		case 3:
			buf[buf.length - 1] &= 0xf8;
			break;
		case 4:
			buf[buf.length - 1] &= 0xf0;
			break;
		case 5:
			buf[buf.length - 1] &= 0xe0;
			break;
		case 6:
			buf[buf.length - 1] &= 0xc0;
			break;
		case 7:
			buf[buf.length - 1] &= 0x80;
			break;
		}
		buf = Buffer.concat([ uint2b(bits), buf ]);
		return buf;
	};

	this.transform = function(decrypt, input) {
		var blb, lhblb;
		if (! validArr(input)) {
			throw new Error('Bad input data');
		}
		if (blockLengthBits !== undefined) {
			if (input.length !== blockLengthBits) {
				throw new Error('Input block size mismatch');
			}
			blb = blockLengthBits;
		} else if (input.length >= 2) {
			blb = input.length;
		} else {
			throw new Error('Too short input block');
		}
		if (leftHalfBlockLengthBits === undefined) {
			lhblb = blb - (blb >> 1);
		} else {
			lhblb = leftHalfBlockLengthBits;
		}
		var k = Buffer.concat([ key,
								uint2b(blb),
								uint2b(lhblb),
								uint2b(rounds) ]);
		var i, l, r, t;
		if (decrypt) {
			r = input.slice(0, lhblb);
			l = input.slice(lhblb);
		} else {
			l = input.slice(0, lhblb);
			r = input.slice(lhblb);
		}
		for (i = 0; i < rounds; i++) {
			t = skh(Buffer.concat([k, uint2b(decrypt ? (rounds - i - 1) : i), a2b(r)]),
					l.length,
					hashAlgorithm);
			if (t === undefined) {
				throw new Error('Hash failure');
			}
			t = b2a(t);
			if (t === undefined) {
				throw new Error('Internal error');
			}
			t = axor(l, t);
			l = r;
			r = t;
		}
		if (decrypt) {
			return r.concat(l);
		} else {
			return l.concat(r);
		}
	}.bind(this);

	this.transformNum = function(decrypt, input) {
		if (blockLengthBits === undefined) {
			throw new Error('Numeric block without fixed block size');
		}
		input = i2a(input, blockLengthBits);
		if (input === undefined) {
			throw new Error('Bad numeric input');
		}
		return this.transform(decrypt, input);
	}.bind(this);

};

ArbitraryBlockFeistelHashCipher.prototype.encrypt = function(input) {
	if (typeof (this.transform) !== 'function') {
		throw new Error('Cipher object in error state');
	}
	if (typeof(input) === 'string') {
		input = s2a(input);
	} else if (Buffer.isBuffer(input)) {
		input = b2a(input);
	}
	var rv = this.transform(false, input);
	if (rv === undefined) {
		throw new Error('Encryption failed');
	}
	return rv;
};

ArbitraryBlockFeistelHashCipher.prototype.decrypt = function(input) {
	if (typeof (this.transform) !== 'function') {
		throw new Error('Cipher object in error state');
	}
	if (typeof(input) === 'string') {
		input = s2a(input);
	} else if (Buffer.isBuffer(input)) {
		input = b2a(input);
	}
	var rv = this.transform(true, input);
	if (rv === undefined) {
		throw new Error('Decryption failed');
	}
	return rv;
};

ArbitraryBlockFeistelHashCipher.prototype.encryptNum = function(input, outputArray) {
	if (typeof (this.transformNum) !== 'function') {
		throw new Error('Cipher object in error state');
	}
	var rv = this.transformNum(false, input);
	if (rv === undefined) {
		throw new Error('Encryption failed');
	}
	return (outputArray ? rv : a2i(rv));
};

ArbitraryBlockFeistelHashCipher.prototype.decryptNum = function(input, outputArray) {
	if (typeof (this.transformNum) !== 'function') {
		throw new Error('Cipher object in error state');
	}
	var rv = this.transformNum(true, input);
	if (rv === undefined) {
		throw new Error('Decryption failed');
	}
	return (outputArray ? rv : a2i(rv));
};

module.exports = ArbitraryBlockFeistelHashCipher;
