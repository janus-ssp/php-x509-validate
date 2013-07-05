<?php
/**
 * Janus X509 Certificate Validator
 *
 * LICENSE
 *
 * Copyright 2013 Janus SSP group
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 *
 * @package
 * @copyright 2010-2013 Janus SSP group
 * @license   http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 */

/**
 * OpenSSL s_client command
 *
 * From the OpenSSL documentation (http://www.openssl.org/docs/apps/s_client.html):
 * "The s_client command implements a generic SSL/TLS client which connects to a remote host using SSL/TLS.
 * It is a very useful diagnostic tool for SSL servers."
 */
class OpenSsl_Command_SClient extends Shell_Command_Abstract
{
    const COMMAND = 'openssl s_client';

    protected $_connectTo;
    protected $_showCerts;
    protected $_certificateAuthorityFile;

    public function setConnectTo($host="localhost", $port=443)
    {
        $this->_connectTo = array(
            'host' => $host,
            'port' => $port,
        );

        return $this;
    }

    public function setShowCerts($showCerts)
    {
        $this->_showCerts = $showCerts;
    }

    public function setCertificateAuthorityFile($file)
    {
        $this->_certificateAuthorityFile = $file;

        return $this;
    }

    public function _buildCommand($arguments = array())
    {
        $command = self::COMMAND;
        if (isset($this->_connectTo)) {
            $command .= " -connect {$this->_connectTo['host']}:{$this->_connectTo['port']}";
        }
        if (isset($this->_showCerts) && $this->_showCerts) {
            $command .= ' -showcerts';
        }
        if (isset($this->_certificateAuthorityFile)) {
            $command .= ' -CAfile ' . escapeshellarg($this->_certificateAuthorityFile);
        }

        return $command;
    }
}
