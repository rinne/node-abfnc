<?php

/*
 *  ABFNC
 *
 *  This is an implementation of arbitrary block size Feistel network
 *  encryption using user selectable cryptographic hash functions as
 *  source of pseudo randomness in round functions.
 *
 *  This PHP implementation is functionally identical to Javascript
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

class ArbitraryBlockFeistelHashCipher {

  private $error;
  private $key;
  private $hashAlgorithm;
  private $rounds;
  private $blockLengthBits;
  private $leftHalfBlockBits;

  function __construct($key,
		       $hashAlgorithm = NULL,
		       $rounds = NULL,
		       $blockLengthBits = NULL,
		       $leftHalfBlockLengthBits = NULL) {
    $this->error = FALSE;
    $this->hashAlgorithm = (empty($hashAlgorithm) ? 'sha512' : $hashAlgorithm);
    $this->rounds = (empty($this->rounds) ? 24 : $rounds);
    $this->blockLengthBits = (empty($blockLengthBits) ? NULL : $blockLengthBits);
    $this->leftHalfBlockLengthBits = (empty($leftHalfBlockLengthBits) ?
				      NULL :
				      $leftHalfBlockLengthBits);
    if (is_string($key)) {
      $this->key = $this->a2s($this->rs2a($key));
    } elseif ($this->validArr($key)) {
      $this->key = $this->a2s(array_slice($key, 0));
    } else {
      $this->error = true;
      trigger_error('Bad key', E_USER_NOTICE);
      return;
    }
    if (! in_array($this->hashAlgorithm, hash_algos(), true)) {
      $this->error = true;
      trigger_error('Invalid hash algorithm', E_USER_NOTICE);
      return;
    }
    if (! (is_int($this->rounds) && ($this->rounds > 5))) {
      $this->error = true;
      trigger_error('Invalid number of rounds', E_USER_NOTICE);
      return;
    }
    if (! (is_null($this->blockLengthBits) ||
	   (is_int($this->blockLengthBits) && ($this->blockLengthBits >= 2)))) {
      $this->error = true;
      trigger_error('Invalid block length', E_USER_NOTICE);
      return;
    }
    if (is_null($this->blockLengthBits)) {
      if (! is_null($this->leftHalfBlockLengthBits)) {
	$this->error = true;
	trigger_error('Invalid block divisor', E_USER_NOTICE);
	return;
      }
    } else {
      if (is_null($this->leftHalfBlockLengthBits)) {
	$this->leftHalfBlockBits = $this->blockLengthBits - ($this->blockLengthBits >> 1);
      } elseif (! (is_int($this->leftHalfBlockLengthBits) &&
		   ($this->leftHalfBlockLengthBits >= 1) &&
		   ($this->leftHalfBlockLengthBits < $this->blockLengthBits))) {
	$this->error = true;
	trigger_error('Invalid block divisor', E_USER_NOTICE);
	return;
      }
    }
  }

  public function encrypt($input) {
    if ($this->error) {
      trigger_error('Cipher in error state', E_USER_NOTICE);
      return FALSE;
    }
    return $this->transform(false, $input);
  }

  public function decrypt($input) {
    if ($this->error) {
      trigger_error('Cipher in error state', E_USER_NOTICE);
      return FALSE;
    }
    return $this->transform(true, $input);
  }

  public function encryptNum($input, $returnArray = FALSE) {
    if ($this->error) {
      trigger_error('Cipher in error state', E_USER_NOTICE);
      return FALSE;
    }
    return $this->transformNum(false, $input, $returnArray);
  }

  public function decryptNum($input, $returnArray = FALSE) {
    if ($this->error) {
      trigger_error('Cipher in error state', E_USER_NOTICE);
      return FALSE;
    }
    return $this->transformNum(true, $input, $returnArray);
  }

  private function validArr($a) {
    if (! is_array($a)) {
      return FALSE;
    }
    if (count($a) < 1) {
      return FALSE;
    }
    foreach ($a as $i) {
      if (($i !== 0) && ($i !== 1)) {
	return FALSE;
      }
    }
    return true;
  }

  private function i2a($in, $bits = NULL) {
    if (! ((is_int($bits) && ($bits > 0)) || empty($bits))) {
	trigger_error('Invalid bit length', E_USER_NOTICE);
	return FALSE;
    }
    $r = [];
    if (is_string($in) && preg_match('/^(0|([1-9][0-9]*))$/', $in)) {
      for ($i = 0;
	   (($i < $bits) || (empty($bits) && (($in !== '0') || ($i == 0))));
	   $i++) {
	array_unshift($r, ((bcmod($in, '2') === '0') ? 0 : 1));
	$in = bcdiv($in, '2');
      }
      if ($in !== '0') {
	trigger_error('Integer overflow', E_USER_NOTICE);
	return FALSE;
      }
    } elseif (is_int($in) && ($in >= 0)) {
      for ($i = 0;
	   (($i < $bits) || (empty($bits) && (($in != 0) || ($i == 0))));
	   $i++) {
	array_unshift($r, $in & 1);
	$in >>= 1;
      }
      if ($in != 0) {
	trigger_error('Integer overflow', E_USER_NOTICE);
	return FALSE;
      }
    } else {
      trigger_error('Invalid integer', E_USER_NOTICE);
      return FALSE;
    }
    return $r;
  }

  private function a2i($a) {
    if (! is_array($a)) {
      trigger_error('Invalid binary array', E_USER_NOTICE);
      return FALSE;
    }
    $r = 0;
    for ($i = 0; $i < count($a); $i++) {
      if (! (($a[$i] === 0) || ($a[$i] === 1))) {
	trigger_error('Invalid binary array', E_USER_NOTICE);
	return FALSE;
      }
      $n = ($r << 1) | $a[$i];
      if ($n < 0) {
	$r = (string)$r;
	for (/*NOTHING*/; $i < count($a); $i++) {
	  if (! (($a[$i] === 0) || ($a[$i] === 1))) {
	    trigger_error('Invalid binary array', E_USER_NOTICE);
	    return FALSE;
	  }
	  $r = bcmul($r, '2');
	  if ($a[$i]) {
	    $r = bcadd($r, '1');
	  }
	}
	return $r;
      }
      $r = $n;
    }
    return $r;
  }

  private function a2s($a) {
    if (! is_array($a)) {
      trigger_error('Invalid binary array', E_USER_NOTICE);
      return FALSE;
    }
    for ($i = 0, $s = pack('NN', 0, count($a)), $c = 0, $p = false; $i < count($a); $i++) {
      if (! (($a[$i] === 0) || ($a[$i] === 1))) {
	trigger_error('Invalid binary array', E_USER_NOTICE);
	return FALSE;
      }
      $p = true;
      if ($a[$i]) {
	$c |= 1 << (7 - ($i & 7));
      }
      if (($i & 7) == 7) {
	$s .= chr($c);
	$c = 0;
	$p = false;
      }
    }
    if ($p) {
      $s .= chr($c);
    }
    return $s;
  }

  private function s2a($s) {
    if (strlen($s) < 4) {
      trigger_error('Invalid binary buffer format', E_USER_NOTICE);
      return FALSE;
    }
    $z = unpack('Nzero/Nbits', $s);
    if ($z['zero'] != 0) {
      trigger_error('Huge binary buffer length', E_USER_NOTICE);
      return FALSE;
    }
    $z = $z['bits'];
    if (strlen($s) < (8 + (int)(ceil($z / 8)))) {
      trigger_error('Invalid binary buffer length', E_USER_NOTICE);
      return FALSE;
    }
  
    for ($i = 0; $i < $z; $i++) {
      $r[] = (ord(substr($s, ($i >> 3) + 8, 1)) >> (7 - ($i & 7))) & 1;
    }
    return $r;
  }

  private function rs2a($buf) {
    return $this->s2a(pack('NN', 0, strlen($buf) << 3) . $buf);
  }

  private function axor($a, $b) {
    $r = [];
    if (! (is_array($a) && is_array($b) && (count($a) == count($b)))) {
      trigger_error('Binary array size mismatch', E_USER_NOTICE);
      return FALSE;
    }
    for ($i = 0; $i < count($a); $i++) {
      if (! ((($a[$i] === 0) || ($a[$i] === 1)) && (($b[$i] === 0) || ($b[$i] === 1)))) {
	trigger_error('Invalid binary array', E_USER_NOTICE);
	return FALSE;
      }
      $r[] = $a[$i] ^ $b[$i];
    }
    return $r;
  }

  private function skh($d, $bits) {
    $b = $this->a2s($this->rs2a($this->hashAlgorithm)) . pack('NN', 0, $bits);
    for ($i = 0, $h = '', $buf = ''; strlen($buf) * 8 < $bits; $i++) {
      $c = @hash_init($this->hashAlgorithm);
      if (empty($c)) {
	trigger_error('Hashing failed', E_USER_NOTICE);
	return FALSE;
      }
      hash_update($c, $b);
      hash_update($c, $d);
      if ($i > 0) {
	hash_update($c, pack('NN', 0, $i));
	hash_update($c, $h);
      }
      $h = hash_final($c, true);
      $buf .= $h;
    }
    $r = $this->s2a(pack('NN', 0, $bits) . $buf); 
    return $r;
  }

  private function transform($decrypt, $input) {
    if (is_string($input)) {
      $input = $this->rs2a($input);
    }
    if (! is_array($input)) {
      trigger_error('Invalid input', E_USER_NOTICE);
      return FALSE;
    }
    if (empty($this->blockLengthBits)) {
      if (count($input) < 2) {
	trigger_error('Invalid block', E_USER_NOTICE);
	return FALSE;
      }
      $blockBits = count($input);
      $leftHalfBlockBits = $blockBits - ($blockBits >> 1);
    } else {
      if (count($input) != $this->blockLengthBits) {
	trigger_error('Block size mismatch', E_USER_NOTICE);
	return FALSE;
      }
      $blockBits = $this->blockLengthBits;
      $leftHalfBlockBits = $this->leftHalfBlockBits;
    }
    $key = $this->key . pack('NNNNNN', 0, $blockBits, 0, $leftHalfBlockBits, 0, $this->rounds);
    if ($decrypt) {
      $r = array_slice($input, 0, $leftHalfBlockBits);
      $l = array_slice($input, $leftHalfBlockBits);
    } else {
      $l = array_slice($input, 0, $leftHalfBlockBits);
      $r = array_slice($input, $leftHalfBlockBits);
    }
    for ($i = 0; $i < $this->rounds; $i++) {
      $tmp = $this->skh($key . pack('NN', 0, ($decrypt ? ($this->rounds - $i - 1) : $i)) . $this->a2s($r), count($l));
      if (empty($tmp)) {
	trigger_error('Subkey hashing failed', E_USER_NOTICE);
	return FALSE;
      }
      $tmp = $this->axor($l, $tmp);
      $l = $r;
      $r = $tmp;
    }
    if ($decrypt) {
      return array_merge($r, $l);
    } else {
      return array_merge($l, $r);
    }
  }

  private function transformNum($decrypt, $input, $returnArray = FALSE) {
    if ($this->validArr($input)) {
      $b = $input;
    } else {
      if (empty($this->blockLengthBits)) {
	trigger_error('Numeric block without fixed block size', E_USER_NOTICE);
	return FALSE;
      }
      $b = $this->i2a($input, $this->blockLengthBits);
      if ($b === FALSE) {
	trigger_error('Invalid input', E_USER_NOTICE);
	return FALSE;
      }
    }
    $b = $this->transform($decrypt, $b);
    if (empty($b)) {
      return FALSE;
    }
    return ($returnArray ? $b : $this->a2i($b));
  }

};
