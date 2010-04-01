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
 * @version    SVN: $Id$
 */
class sfCookieSessionStorage extends sfCookieSessionStorageBase
{
  /**
   * Storage initialization
   *
   * Available option:
   *
   *  - secret:           A secret key (phrase) to ensure strong data encryption/signature
   * And the options of sfCookieSessionStorageBase:
   *  - use_compression:  whether to compress the session data in the cookie (requires zlib)
   *                      (defaults to false)
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
    
    return parent::initialize($options);
  }

  /**
   * Encodes data 
   *
   * @param  string  $data  Plain text data
   *
   * @return string         Encoded data
   */
  public function encode($data)
  {
    // just sign with a sha1 digest
    $encodedData = base64_encode($data);
    $encodedData = $encodedData . '--' . $this->generateDigest($encodedData);
    
    return $encodedData;
  }
  
  /**
   * Decodes data
   *
   * @param  string  $encodedData  Encoded data
   *
   * @return string                Decoded data
   */
  public function decode($encodedData)
  {
    if(strpos($encodedData, '--') === false)
    {
      return '';
    }
    list($encodedData, $digest) = explode('--', $encodedData, 2);
    if ($digest != $this->generateDigest($encodedData))
    {
      return '';
    }
    return base64_decode($encodedData);
  }

  /**
   * Generate an inline SHA1 message digest, including a secret
   *
   * @param string $data the data to sign
   *
   * @return string the data digest
   */
	protected function generateDigest($data)
	{
		return sha1(sha1($data . $this->options['secret']));
	}
}