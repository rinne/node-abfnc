<?php

require_once('./abfnc.php');

function hd($s) {
  for ($i = 0, $p = false; $i < strlen($s); $i++) {
    $p = true;
    if (($i & 15) == 0) {
      printf("%08x ", $i);
    }
    printf(" %02x", ord(substr($s, $i, 1)));
    if (($i & 15) == 15) {
      printf("\n");
      $p = false;
    }
  }
  if ($p) {
    printf("\n");
    $p = false;
  }
}

function uuidGen($n, $key) {
  if (! ((is_int($n) && ($n > 0)) || (is_string($n) && preg_match('/^(0|([1-9][0-9]*))$/', $n)))) {
    return false;
  }
  if (bccomp((string)$n, '18446744073709551615') > 0) {
    return false;
  }
  $c = new ArbitraryBlockFeistelHashCipher($key, NULL, NULL, 122);
  $a = $c->encryptNum($n, true);
  $a = array_merge(array_slice($a, 0, 48),
		   [0, 1, 0, 0],
		   array_slice($a, 48, 12),
		   [1, 0],
		   array_slice($a, 60));
  $h = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
  $r = '';
  for ($i = 0; count($a) >= 4; $i++) {
    $r .= $h[((((($a[0] << 1) | $a[1]) << 1) | $a[2]) << 1) | $a[3]];
    $a = array_slice($a, 4);
    if (($i == 7) || ($i == 11) || ($i == 15) || ($i == 19)) {
      $r .= '-';
    }
  }
  return $r;
}

function uuidCheck($u, $key) {
  $m = null;
  if (! (is_string($u) && preg_match('/^([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])-([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])-(4)([0-9a-f])([0-9a-f])([0-9a-f])-([89ab])([0-9a-f])([0-9a-f])([0-9a-f])-([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])([0-9a-f])$/', $u, $m))) {
    return false;
  }
  array_shift($m);
  $h = ['0' => [0, 0, 0, 0],
	'1' => [0, 0, 0, 1],
	'2' => [0, 0, 1, 0],
	'3' => [0, 0, 1, 1],
	'4' => [0, 1, 0, 0],
	'5' => [0, 1, 0, 1],
	'6' => [0, 1, 1, 0],
	'7' => [0, 1, 1, 1],
	'8' => [1, 0, 0, 0],
	'9' => [1, 0, 0, 1],
	'a' => [1, 0, 1, 0],
	'b' => [1, 0, 1, 1],
	'c' => [1, 1, 0, 0],
	'd' => [1, 1, 0, 1],
	'e' => [1, 1, 1, 0],
	'f' => [1, 1, 1, 1] ];
  $r = [];
  foreach ($m as $d) {
    $r = array_merge($r, $h[$d]);
  }
  $v4 = array_slice($r, 48, 4);
  if ($v4 !== [0, 1, 0, 0]) {
    return false;
  }
  $vr = array_slice($r, 64, 2);
  if ($vr !== [1, 0]) {
    return false;
  }
  $r = array_merge(array_slice($r, 0, 48), array_slice($r, 52, 12), array_slice($r, 66));
  $c = new ArbitraryBlockFeistelHashCipher($key, NULL, NULL, 122);
  $r = $c->decryptNum($r);
  if (bccomp((string)$r, '18446744073709551615') > 0) {
    return false;
  }
  return $r;
}

/*
for ($i = 0; $i < 100; $i++) {
  $u = uuidGen($i, 'foo');
  $c = uuidCheck($u, 'foo');
  printf("%s -> %s -> %s\n", $i, $u, $c);
}

foreach(['18446744073709551614', '18446744073709551615', '18446744073709551616'] as $i) {
  $u = uuidGen($i, 'foo');
  $c = uuidCheck($u, 'foo');
  printf("%s -> %s -> %s\n", $i, $u, $c);
}
*/

/*
//hd(a2s(skh('foo', 'bar', 'crc32', 42)));
//hd(a2s(skh('foo', 'baz', 'crc32', 42)));
print_r(skh('foo', 'crc32', 71));
print_r(skh('foo', 'crc32', 72));
print_r(a2s(skh('foo', 'crc32', 71)));
print_r(a2s(skh('foo', 'crc32', 72)));

$k = [0,0,0,0,0,0,0,0,0,0];
$p0 = [1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1];
print_r($p0);
$c0 = encr($p0, $k);
print_r($c0);
$p1 = decr($c0, $k);
print_r($p1);
*/

/*
$c = new ArbitraryBlockFeistelHashCipher('secret', NULL, NULL, 65);
for ($x = 0; $x < 1000; $x++) {
  $y = $c->encryptNum($x);
  if ($y === FALSE) {
    printf("%s -> %s -> %s\n", (string)$x, 'ERROR', '???');
  } else {
    $z = $c->decryptNum($y);
    if ($z === FALSE) {
      printf("%s -> %s -> %s\n", (string)$x, (string)$y, 'ERROR');
    } else {
      printf("%s -> %s -> %s%s\n", (string)$x, (string)$y, (string)$z, (($x === $z) ? '' : '  ERROR!!!'));
      //var_dump($x);
      //var_dump($y);
      //var_dump($z);
    }
  }
}
*/

/*
//$a = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
$a = [0,0,1,0,1,1,0,1,1,1,0,1,1,1,1,0,1,1,1,1,1,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0];

foreach(['secret', 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.', 'foo'] as $k) {
  foreach(['md5','sha1','sha256','sha512'] as $h) {
    $x = new ArbitraryBlockFeistelHashCipher($k, $h);
    echo(implode('', $a)."\n");
    $b = $x->encrypt($a);
    echo(implode('', $b)."\n");
    $c = $x->decrypt($b);
    echo(implode('', $c)."\n");
  }
}
*/

$bits = 16;
$c = new ArbitraryBlockFeistelHashCipher('foo', 'md5', 24, $bits);
for ($x = 0; $x < min(100, (1 << $bits)); $x++) {
  $y = $c->encryptNum($x);
  if ($y === FALSE) {
    printf("%s -> %s -> %s\n", (string)$x, 'ERROR', '???');
  } else {
    $z = $c->decryptNum($y);
    if ($z === FALSE) {
      printf("%s -> %s -> %s\n", (string)$x, (string)$y, 'ERROR');
    } else {
      printf("%s -> %s -> %s%s\n", (string)$x, (string)$y, (string)$z, (($x === $z) ? '' : '  ERROR!!!'));
      //var_dump($x);
      //var_dump($y);
      //var_dump($z);
    }
  }
}
