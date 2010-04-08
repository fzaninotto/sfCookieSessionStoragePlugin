<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Cookie-based session storage. Session data is directly stored in a cookie,
 * only on the client side (no persistent session on the server side)
 *
 * @package    symfony
 * @subpackage storage
 * @author     Nicolas Perriault <nicolas.perriault@symfony-project.org>
 * @author     François Zaninotto
 */
abstract class sfCookieSessionStorageBase extends sfSessionStorage
{
  const COMPRESSION_LEVEL = 9;

  /**
   * Storage initialization
   *
   * Available option:
   *
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
      'use_compression' => false,
      'cookie_name'     => null,
    ), $options, array(
      // values that can't be changed
      'auto_start'      => false
    ));
    
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
  	$cookieName = $this->getCookieName($id);
    return isset($_COOKIE[$cookieName]) ? $this->decode($this->uncompress($_COOKIE[$cookieName]), $id) : '';
  }

  /**
   * Removes session id
   *
   * @param string $id
   */
  public function sessionDestroy($id)
  {
    return @setcookie($this->getCookieName($id), null, strtotime('1 year ago'));
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

    if (strlen($encData = $this->compress($this->encode($data, $id))) > 4096)
    {
      throw new LengthException(sprintf('Cookie based session storage cannot store more than 4096 Bytes of data (you provided %d)', strlen($encData)));
    }

    // sets the cookie containing the session data
    $ok = @setcookie($this->getCookieName($id), $encData, $lifeTime, $this->options['session_cookie_path'], $this->options['session_cookie_domain'], $this->options['session_cookie_secure'], $this->options['session_cookie_httponly']);

    // sends output buffering and turn it off
    !ob_get_length() or ob_end_flush();

    return $ok;
  }

  /**
   * Get the configured name of the session data cookie
   *
   * @param  string  $id The session id
   *
   * @return string         Cookie name
   */
	protected function getCookieName($id)
	{
		return null === $this->options['cookie_name'] ? $id : $this->options['cookie_name'];
	}
	
  /**
   * Compresses data 
   *
   * @param  string  $data  Plain text data
   *
   * @return string         Encoded data
   */
  protected function compress($data)
  {
    if (!$data)
    {
      return '';
    }

    if ($this->options['use_compression'])
    {
      $data = gzdeflate($data, self::COMPRESSION_LEVEL);
    }
    
    return $data;
  }
  
  /**
   * Uncompresses data
   *
   * @param  string  $data  Encoded data
   *
   * @return string                Decoded data
   */
  protected function uncompress($data)
  {
    if ($this->options['use_compression'])
    {
      $data = gzinflate($data);
    }
    
    return $data;
  }
  
  /**
   * Encodes data 
   *
   * @param  string  $data  Plain text data
   * @param  string  $id The session id
   *
   * @return string         Encoded data
   */
  abstract function encode($data, $id);
  
  /**
   * Decodes data
   *
   * @param  string  $encodedData  Encoded data
   * @param  string  $id The session id
   *
   * @return string                Decoded data
   */
  abstract function decode($encodedData, $id);
}