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
