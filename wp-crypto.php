<?php

  /*
   * THIS FILE MUST BE PROTECTED, THIS KEY MUST BE DIFFERENT ON EVERY PROJECT
   * IN CASE OF INFRASTRUCTURE COMPROMISE:
   * 1. SECURE THE SERVER
   * 2. GENERATE A NEW KEY
   * 3. RE-ENCRYPT DATA WITH THE NEW KEY (ROTATE KEY):
   *    $plaintext = Crypto::decrypt($ciphertext, $oldKey);
   *    return Crypto::encrypt($plaintext, $newKey);
   */

  // Deny file direct access
  if (basename($_SERVER['PHP_SELF']) == basename(__FILE__)){ die('No direct access allowed.'); }

  // THE KEY MUST BE OF 16 BYTES, GENERATED WITH php-encryption lib [https://github.com/defuse/php-encryption] method: Key::CreateNewRandomKey()
  // Ex. echo \Defuse\Crypto\Key::CreateNewRandomKey()->saveToAsciiSafeString();
  define('ELSEWHERE_KEY','');

?>
