<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Cookie-based session storage. Session data is directly stored in an encrypted
 * cookie, only on the client side (no persistent session on the server side)
 *
 * @package    symfony
 * @subpackage storage
 * @author     Nicolas Perriault <nicolas.perriault@symfony-project.org>
 * @author     François Zaninotto
 * @version    SVN: $Id$
 */
class sfCookieSessionStorage extends sfSessionStorage
{
  const COMPRESSION_LEVEL = 9;

  /**
   * Storage initialization
   *
   * Available option:
   *
   *  - secret:           A secret key (phrase) to ensure strong data encryption/signature
   *  - use_crypt:        Whether to crypt session data in the cookie (requires mcrypt)
   *                      If you use suhosin, this is not necessary since suhosin does it for you
   *  - encode_callable:  A PHP callable or sfCallable instance to encrypt data
   *  - decode_callable:  A PHP callable or sfCallable instance to decrypt data
   *
   * @param  array  $options  Session storage options
   *
   * @throws sfConfigurationException if configuration is invalid
   */
  public function initialize($options = array())
  {
    $options = array_merge(array(
      // default values
      'use_compression' => false,
      'use_crypt'       => true,
      'crypt_algorithm' => 'tripledes',
      'crypt_mode'      => 'ecb',
      'encode_callable' => array($this, 'sign'),
      'decode_callable' => array($this, 'unsign'),
    ), $options, array(
      // values that can't be changed
      'auto_start'      => false
    ));
    
    if (!isset($options['secret']) || !trim((string)$options['secret'])) 
    { 
      throw new sfConfigurationException('You must define a `secret` key in the storage params of your `factories.yml` in order to use the cookie based session storage'); 
    }
 	
    if (isset($options['use_crypt']) && $options['use_crypt'])
    {
      if (extension_loaded('mcrypt'))
      {
        $options['encode_callable'] = array($this, 'encrypt');
        $options['decode_callable'] = array($this, 'decrypt');
      }
      else
      {
        throw new sfConfigurationException('Mcrypt module is not installed or enabled, but is required in order to use default encryption system.');
      }
    }
    
    if (isset($options['use_compression']) && $options['use_compression'] && !extension_loaded('zlib'))
    {
      throw new sfConfigurationException('zlib extension is required to allow compression of session data in the cookie');
    }
    
    parent::initialize($options);
    
    // turn on output buffering, it will be closed at write time
    ob_start();

    // use this object as the session handler
    session_set_save_handler(
      array($this, 'sessionOpen'),
      array($this, 'sessionClose'),
      array($this, 'sessionRead'),
      array($this, 'sessionWrite'),
      array($this, 'sessionDestroy'),
      array($this, 'sessionGC')
    );

    // start our session
    @session_start();
  }

  /**
   * Closes the session
   *
   * @return Boolean
   */
  public function sessionClose()
  {
    return true;
  }

  /**
   * Handles the session garabage collection.
   *
   * @param int $lifeTime
   *
   * @return Boolean
   */
  public function sessionGC($lifeTime)
  {
    return true;
  }

  /**
   * Opens a session.
   *
   * @return Boolean
   */
  public function sessionOpen($path, $name)
  {
    return true;
  }

  /**
   * Reads session data
   *
   * @param  string $key
   *
   * @return string
   */
  public function sessionRead($id)
  {
    return isset($_COOKIE[$id]) ? $this->decode($_COOKIE[$id]) : '';
  }

  /**
   * Removes session id
   *
   * @param string $id
   */
  public function sessionDestroy($id)
  {
    return @setcookie($id, null, strtotime('1 year ago'));
  }

  /**
   * Writes session data
   *
   * @param  string $id
   * @param  mixed  $data
   *
   * @return Boolean
   *
   * @throws LengthException if data is too large to be contained in a cookie (4KB max)
   */
  public function sessionWrite($id, $data)
  {
    // calculates cookie expiration date
    if ($lifeTime = $this->options['session_cookie_lifetime'] > 0)
    {
      $lifeTime += time();
    }

    if (strlen($encData = $this->encode($data)) > 4096)
    {
      throw new LengthException(sprintf('Cookie based session storage cannot store more than 4096 Bytes of data (you provided %d)', strlen($encData)));
    }

    // sets the cookie containing the session data
    $ok = @setcookie($id, $encData, $lifeTime, $this->options['session_cookie_path'], $this->options['session_cookie_domain'], $this->options['session_cookie_secure'], $this->options['session_cookie_httponly']);

    // sends output buffering and turn it off
    !ob_get_length() or ob_end_flush();

    return $ok;
  }

  /**
   * Encodes data 
   *
   * @param  string  $data  Plain text data
   *
   * @return string         Encoded data
   */
  protected function encode($data)
  {
    $encodedData = $this->checkCallable('encode_callable', $data);

    if (!$encodedData)
    {
      return '';
    }

    if ($this->options['use_compression'])
    {
      $encodedData = gzdeflate($encodedData, self::COMPRESSION_LEVEL);
    }
    
    return $encodedData;
  }
  
  /**
   * Decodes data
   *
   * @param  string  $encodedData  Encoded data
   *
   * @return string                Decoded data
   */
  protected function decode($encodedData)
  {
    if ($this->options['use_compression'])
    {
      $encodedData = gzinflate($encodedData);
    }
    return $this->checkCallable('decode_callable', $encodedData);
  }
  
  // TripleDES encryption methods
  
  public function encrypt($data)
  {
    $td = $this->initCrypt();

    $encodedData = mcrypt_generic($td, $data);

    $this->deinitCrypt($td);
    
    return base64_encode($encodedData);
  }
  
  public function decrypt($encodedData)
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
  
  // sha1 signature methods
  
  public function sign($data)
  {
    // just sign with a sha1 digest
    $encodedData = base64_encode($data);
    $encodedData = $encodedData . '--' . $this->generateDigest($encodedData);
    
    return $encodedData;
  }

  public function unsign($encodedData)
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
   * Checks if a encoding/decoding callable has been set, and if so return its
   * execution result
   *
   * @param  string  $optionName  The option name (encode_callable or decode_callable)
   * @param  string  $data        The data to encode/decode
   *
   * @return string|null
   *
   * @throws BadMethodCallException if no callable has been found for the given option name
   */
  protected function checkCallable($optionName, $data)
  {
    if (isset($this->options[$optionName]))
    {
      $callable = $this->options[$optionName];

      if ($callable instanceof sfCallable)
      {
        return $callable->call($data);
      }
      else if (is_callable($callable))
      {
        return call_user_func($callable, $data);
      }
    }

    throw new BadMethodCallException('No callback found');
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