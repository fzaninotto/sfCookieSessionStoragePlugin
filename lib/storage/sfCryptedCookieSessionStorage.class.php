<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Crypted cookie session storage. Uses mcrypt for encryption/decryption.
 *
 * @package    symfony
 * @subpackage storage
 * @author     Nicolas Perriault <nicolas.perriault@symfony-project.org>
 * @author     François Zaninotto
 */
class sfCryptedCookieSessionStorage extends sfCookieSessionStorageBase
{
  /**
   * Storage initialization
   *
   * Available option:
   *
   *  - secret:           A secret key (phrase) to ensure strong data encryption/signature
   *  - crypt_algorithm:  The algorithm to use for encryption defaults to tripledes)
   *  - crypt_mode:       The mode to use for encryption (defaults to ecb)
   *  - crypt_iv:         The initialization vector to use for encryption (defaults to 00000)
   * And the options of sfCookieSessionStorageBase:
   *  - use_compression:  whether to compress the session data in the cookie (requires zlib)
   *                      (defaults to false)
   *  - cookie_name:  name of the session data cookie (defaults to the session id)
   *
   * @param  array  $options  Session storage options
   *
   * @throws sfConfigurationException if configuration is invalid
   */
  public function initialize($options = array())
  {
    $options = array_merge(array(
      // default values
      'crypt_algorithm' => 'tripledes',
      'crypt_mode'      => 'ecb',
    ), $options);
    
    if (!isset($options['secret']) || !trim((string)$options['secret'])) 
    { 
      throw new sfConfigurationException('You must define a `secret` key in the storage params of your `factories.yml` in order to use the cookie based session storage'); 
    }
 	
    if (!extension_loaded('mcrypt'))
    {
      throw new sfConfigurationException('Mcrypt module is not installed or enabled, but is required in order to use default encryption system.');
    }
    
    return parent::initialize($options);
  }
  
  /**
   * Encodes data 
   *
   * @param  string  $data  Plain text data
   * @param  string  $id The session id
   *
   * @return string         Encoded data
   */
  public function encode($data, $id)
  {
    $td = $this->initCrypt();

    $encodedData = mcrypt_generic($td, $data);

    $this->deinitCrypt($td);
    
    return base64_encode($encodedData);
  }
  
  /**
   * Decodes data
   *
   * @param  string  $encodedData  Encoded data
   * @param  string  $id The session id
   *
   * @return string                Decoded data
   */
  public function decode($encodedData, $id)
  {
    $encodedData = base64_decode($encodedData);
    
    $td = $this->initCrypt();

    $data = rtrim(mdecrypt_generic($td, $encodedData), "\0");
    
    $this->deinitCrypt($td);
    
    return $data;
  }
  
  protected function initCrypt()
  {
    $td = mcrypt_module_open($this->options['crypt_algorithm'], '', $this->options['crypt_mode'], '');
    $iv = isset($this->options['crypt_iv']) ? $this->options['crypt_iv'] : str_repeat('0', mcrypt_enc_get_iv_size($td));
    $maxKeySize = mcrypt_enc_get_key_size($td);
    if (strlen($this->options['secret']) > $maxKeySize)
    {
      $this->options['secret'] = substr($this->options['secret'], 0, $maxKeySize);
    }
    mcrypt_generic_init($td, $this->options['secret'], $iv);
    
    return $td;
  }
  
  protected function deinitCrypt($td)
  {
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
  }
}