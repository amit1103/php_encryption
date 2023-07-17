<?php

/**
 * Simple string encryption/decryption function.
 * CHANGE $secret_key and $secret_iv !!!
**/

function stringEncryption($action, $string){
  $output = false;
  
  $encrypt_method = 'AES-256-CBC'; // Default
  $secret_key = 'A1M7564M2346I6804T';              
  $secret_iv = '!MA@_#9';  
  
  // hash
  $key = hash('sha256', $secret_key);
  
  // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
  $iv = substr(hash('sha256', $secret_iv), 0, 16);
  
  if( $action == 'encrypt' ) {
      $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
      $output = base64_encode($output);
  }
  else if( $action == 'decrypt' ){
      $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
  }
  
  return $output;
}

/**
 * Example
 * 
**/

echo '<pre>';
$info = 'mypassword';
echo 'info = '.$info."\n";
$encrypted = stringEncryption('encrypt', $info);
echo 'encrypted = '.$encrypted."\n";
$decrypted = stringEncryption('decrypt', $encrypted);
echo 'decrypted = '.$decrypted."\n";
echo '</pre>';

?>