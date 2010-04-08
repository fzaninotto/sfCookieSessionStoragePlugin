<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Signed cookie session storage. Session data stored in clear on the client side,
 * but the client can't change the stored data because of a digest check.
 *
 * @package    symfony
 * @subpackage storage
 * @author     Nicolas Perriault <nicolas.perriault@symfony-project.org>
 * @author     François Zaninotto
 */
class sfCookieSessionStorage extends sfCookieSessionStorageBase
{
  /**
   * Storage initialization
   *
   * Available option:
   *
   *  - secret:           A secret key (phrase) to ensure strong data encryption/signature
   *  - use_encoding:     Whether to encode session data in base64 (defaults to true)
   * And the options of sfCookieSessionStorageBase:
   *  - use_compression:  Whether to compress the session data in the cookie (requires zlib)
   *                      (defaults to false)
   *  - cookie_name:  name of the session data cookie (defaults to the session id)
   *
   * @param  array  $options  Session storage options
   *
   * @throws sfConfigurationException if configuration is invalid
   */
  public function initialize($options = array())
  {
    if (!isset($options['secret']) || !trim((string)$options['secret'])) 
    { 
      throw new sfConfigurationException('You must define a `secret` key in the storage params of your `factories.yml` in order to use the cookie based session storage'); 
    }
    
    $options = array_merge(array(
      // default values
      'use_encoding' => true,
    ), $options);
    
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
    // just sign with a sha1 digest
    $encodedData = $this->options['use_encoding'] ? base64_encode($data) : $data;
    $encodedData = $encodedData . '--' . $this->generateDigest($encodedData, $id);
    
    return $encodedData;
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
    if(strpos($encodedData, '--') === false)
    {
      return '';
    }
    list($encodedData, $digest) = explode('--', $encodedData, 2);
    if ($digest != $this->generateDigest($encodedData, $id))
    {
      return '';
    }
    return $this->options['use_encoding'] ? base64_decode($encodedData) : $encodedData;
  }

  /**
   * Generate an inline SHA1 message digest, including a secret
   *
   * @param string $data the data to sign
   * @param  string  $id The session id
   *
   * @return string the data digest
   */
	protected function generateDigest($data, $id)
	{
		return sha1(sha1($data . $this->options['secret']));
	}
}