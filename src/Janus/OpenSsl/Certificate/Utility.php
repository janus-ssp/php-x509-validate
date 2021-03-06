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
 * Utility class dealing with certificates.
 */
class Janus_OpenSsl_Certificate_Utility
{
    /**
     * Look for PEM encoded certs in text (like Mozillas CA bundle).
     *
     * @static
     * @param  string $text
     * @return array  Certificates found (array of Janus_OpenSsl_Certificate objects)
     */
    public static function getCertificatesFromText($text)
    {
        $inputLines = explode(PHP_EOL, $text);
        $certificatesFound = array();
        $recording = false;
        $certificate = "";
        foreach ($inputLines as $inputLine) {
            if (trim($inputLine) === "-----BEGIN CERTIFICATE-----") {
                $certificate = "";

                $recording = true;
            }

            if ($recording) {
                $certificate .= $inputLine . PHP_EOL;
            }

            if (trim($inputLine) === "-----END CERTIFICATE-----") {
                $certificate = new Janus_OpenSsl_Certificate($certificate);
                $certificatesFound[$certificate->getSubjectDN()] = $certificate;
                $recording = false;
            }
        }

        return $certificatesFound;
    }
}
