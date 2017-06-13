<?php

/**
 * Class Ponvif
 *
 * @author Lorenzo Toscano <lorenzo.toscano@gmail.com>
 * @author KuroNeko
 * @author Rickerd <rick@rickdegraaff.nl>
 *
 * @version 2.0
 * @desc The Onvif client class
 */
class Ponvif
{

    /**
     * @var string ip address of the NVT device
     */
    private $ipAddress='';

    /**
     * @var string NVT authentication username
     */
    private $username='';

    /**
     * @var string NVT authentication password
     */
    private $password='';

    /**
     * @var string media web service uri
     */
    private $mediaUri='';

    /**
     * @var string core web service uri
     */
    private $deviceUri='';

    /**
     * @var string ptz web service uri
     */
    private $ptzUri='';

    /**
     * @var string url of the NVT (without service specification)
     */
    private $baseUri='';

    /**
     * @var array onvif version supported by the NVT
     */
    private $onvifVersion= [];

    /**
     * @var int time differential correction (used to synchronize NVC with NVT)
     */
    private $deltatime=0;

    /**
     * @var array response of GetCapabilities
     */
    private $capabilities= [];

    /**
     * @var array response of GetVideoSources
     */
    private $videosources= [];

    /**
     * @var array containing tokens for further requests
     */
    private $sources= [];

    /**
     * @var array response of GetProfiles
     */
    private $profiles= [];

    /**
     * @var string proxy ipAddress
     */
    private $proxyHost='';

    /**
     * @var string proxy portnumber
     */
    private $proxyPort='';

    /**
     * @var string proxy authentication username
     */
    private $proxyUsername='';

    /**
     * @var string proxy authentication password
     */
    private $proxyPassword='';

    /**
     * @var string last soap response
     */
    private $lastResponse='';

    private $breakOnError=true;

    /**
     * @var int WS-Discovery waiting time (sec)
     */
    private $discoveryTimeout=2;

    /**
     * @var string dicovery ipAddress
     */
    private $discoveryBindIp='';

    /**
     * @var string WS-Discovery multicast ip address
     */
    private $discoveryMulticastIp='';

    /**
     * @var int WS-Discovery multicast port
     */
    private $discoveryMulticastPort=3702;

    /**
     * @var bool WS-Discovery flag to show\hide duplicates via source IP
     */
    private $discoveryHideDuplicates=true;

    public function setProxyHost($proxyHost)
    {
        $this->proxyHost = $proxyHost;
    }

    public function getProxyHost()
    {
        return $this->proxyHost;
    }

    public function setProxyPort($proxyPort)
    {
        $this->proxyPort = $proxyPort;
    }

    public function getProxyPort()
    {
        return $this->proxyPort;
    }

    public function setProxyUsername($proxyUsername)
    {
        $this->proxyUsername = $proxyUsername;
    }

    public function getProxyUsername()
    {
        return $this->proxyUsername;
    }

    public function setProxyPassword($proxyPassword)
    {
        $this->proxyPassword = $proxyPassword;
    }

    public function getProxyPassword()
    {
        return $this->proxyPassword;
    }

    public function setUsername($username)
    {
        $this->username = $username;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function setPassword($password)
    {
        $this->password = $password;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function getDeviceUri()
    {
        return $this->deviceUri;
    }

    public function setDeviceUri($deviceUri)
    {
        $this->deviceUri = $deviceUri;
    }

    public function getIPAddress()
    {
        return $this->ipAddress;
    }

    public function setIPAddress($ipAddress)
    {
        $this->ipAddress = $ipAddress;
    }

    public function getSources()
    {
        return $this->sources;
    }

    public function getMediaUri()
    {
        return $this->mediaUri;
    }

    public function setMediaUri($mediaUri)
    {
        $this->mediaUri = $mediaUri;
    }

    public function getCodecEncoders($codec)
    {
        return $this->_getCodecEncoders($codec);
    }

    public function getPTZUri()
    {
        return $this->ptzUri;
    }

    public function getBaseUrl()
    {
        return $this->baseUri;
    }

    public function getSupportedVersion()
    {
        return $this->onvifVersion;
    }

    public function getCapabilities()
    {
        return $this->capabilities;
    }

    public function setBreakOnError($breakOnError)
    {
        $this->breakOnError=$breakOnError;
    }

    public function getLastResponse()
    {
        return $this->lastResponse;
    }

    public function setDiscoveryTimeout($discoveryTimeout)
    {
        $this->discoveryTimeout = $discoveryTimeout;
    }

    public function setDiscoveryBindIp($discoveryBindIp)
    {
        $this->discoveryBindIp = $discoveryBindIp;
    }

    public function setDiscoveryMcastIp($discoveryMulticastIp)
    {
        $this->discoveryMulticastIp = $discoveryMulticastIp;
    }

    public function setDiscoveryMcastPort($discoveryMulticastPort)
    {
        $this->discoveryMulticastPort = $discoveryMulticastPort;
    }

    public function setDiscoveryHideDuplicates($discoveryHideDuplicates)
    {
        $this->discoveryHideDuplicates = $discoveryHideDuplicates;
    }

    /**
     * WS-Discovery
     *
     * @return array
     */
    public function discover()
    {
        $result      = [];
        $timeout     = time() + $this->discoveryTimeout;
        $post_string = '<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header><w:MessageID>uuid:84ede3de-7dec-11d0-c360-f01234567890</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>';

        try {
            if (false == ($sock = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP))) {
                echo('Create socket error: [' . socket_last_error() . '] ' . socket_strerror(socket_last_error()));
            }
            if (false == socket_bind($sock, $this->discoveryBindIp, rand(20000, 40000))) {
                echo('Bind socket error: [' . socket_last_error() . '] ' . socket_strerror(socket_last_error()));
            }
            socket_set_option($sock, IPPROTO_IP, MCAST_JOIN_GROUP, ['group' => $this->discoveryMulticastIp]);
            socket_sendto($sock, $post_string, strlen($post_string), 0, $this->discoveryMulticastIp, $this->discoveryMulticastPort);
            socket_set_nonblock($sock);

            while (time() < $timeout) {
                if (false !== @socket_recvfrom($sock, $response, 9999, 0, $from, $this->discoveryMulticastPort)) {
                    if ($response != null && $response != $post_string) {
                        $response = $this->_xml2array($response);
                        if (! $this->isFault($response)) {
                            $response['Envelope']['Body']['ProbeMatches']['ProbeMatch']['IPAddr'] = $from;

                            if ($this->discoveryHideDuplicates) {
                                $result[$from] = $response['Envelope']['Body']['ProbeMatches']['ProbeMatch'];
                            } else {
                                $result[] = $response['Envelope']['Body']['ProbeMatches']['ProbeMatch'];
                            }
                        }
                    }
                }
            }
            socket_close($sock);
        } catch (Exception $e) {
            // nothing to catch
        }
        sort($result);

        return $result;
    }

    /**
     * Public functions (basic initialization method and other collaterals)
     */
    public function initialize()
    {
        if (! $this->mediaUri) {
            $this->mediaUri='http://' . $this->ipAddress . '/onvif/device_service';
        }

        try {
            $datetime =$this->core_GetSystemDateAndTime();
            $timestamp=mktime($datetime['Time']['Hour'], $datetime['Time']['Minute'], $datetime['Time']['Second'],
                  $datetime['Date']['Month'], $datetime['Date']['Day'], $datetime['Date']['Year']);
            $this->deltatime=time() - $timestamp - 5;
        } catch (Exception $e) {
        }

        $this->capabilities=$this->core_GetCapabilities();
        $onvifVersion      =$this->_getOnvifVersion($this->capabilities);
        $this->mediaUri    =$onvifVersion['media'];
        $this->deviceUri   =$onvifVersion['device'];
        $this->ptzUri      =$onvifVersion['ptz'];
        preg_match("/^http(.*)onvif\//", $this->mediaUri, $matches);
        $this->baseUri     =$matches[0];
        $this->onvifVersion=['major'=> $onvifVersion['major'],
                      'minor'       => $onvifVersion['minor'], ];

        $this->videosources=$this->media_GetVideoSources();
        $this->profiles    =$this->media_GetProfiles();
        $this->sources     =$this->_getActiveSources($this->videosources, $this->profiles);
    }

    /**
     * Useful to check if response contains a fault
     *
     * @param $response
     *
     * @return bool
     */
    public function isFault($response)
    {
        return array_key_exists('Fault', $response) || array_key_exists('Fault', $response['Envelope']['Body']);
    }

    /**
     * Public wrappers for a subset of ONVIF primitives
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function core_GetSystemDateAndTime()
    {
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>';
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetSystemDateAndTime: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetSystemDateAndTimeResponse']['SystemDateAndTime']['UTCDateTime'];
        }
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function core_GetCapabilities()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>All</Category></GetCapabilities></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'], ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetCapabilities: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetCapabilitiesResponse']['Capabilities'];
        }
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetVideoSources()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'], ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetVideoSources: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetVideoSourcesResponse']['VideoSources'];
        }
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetProfiles()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'], ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetProfiles: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetProfilesResponse']['Profiles'];
        }
    }

    /**
     * @throws Exception
     */
    public function media_GetServices()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"><IncludeCapability>false</IncludeCapability></GetServices></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'], ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetServices: Communication error');
            }
        }
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function core_GetDeviceInformation()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'], ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetDeviceInformation: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetDeviceInformationResponse'];
        }
    }

    /**
     * @param $profileToken
     * @param string $stream
     * @param string $protocol
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetStreamUri($profileToken, $stream='RTP-Unicast', $protocol='RTSP')
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl"><StreamSetup><Stream xmlns="http://www.onvif.org/ver10/schema">%%STREAM%%</Stream><Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>%%PROTOCOL%%</Protocol></Transport></StreamSetup><ProfileToken>%%PROFILETOKEN%%</ProfileToken></GetStreamUri></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%STREAM%%',
                   '%%PROTOCOL%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $stream,
                   $protocol, ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetStreamUri: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetStreamUriResponse']['MediaUri']['Uri'];
        }
    }

    /**
     * @param $profileToken
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetSnapshotUri($profileToken)
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken></GetSnapshotUri></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
        '%%PASSWORD%%',
        '%%NONCE%%',
        '%%CREATED%%',
        '%%PROFILETOKEN%%', ],
        [$REQ['USERNAME'],
            $REQ['PASSDIGEST'],
            $REQ['NONCE'],
            $REQ['TIMESTAMP'],
            $profileToken, ],
        $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetSnapshotUri: Communication error');
            }
            var_dump($response);
        } else {
            return $response['Envelope']['Body']['GetSnapshotUriResponse']['MediaUri']['Uri'];
        }
    }

    /**
     * @param null $filterToken
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetVideoEncoderConfigurations($filterToken = null)
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetVideoEncoderConfigurations xmlns="http://www.onvif.org/ver10/media/wsdl" /></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
            '%%PASSWORD%%',
            '%%NONCE%%',
            '%%CREATED%%', ],
            [$REQ['USERNAME'],
                $REQ['PASSDIGEST'],
                $REQ['NONCE'],
                $REQ['TIMESTAMP'], ],
            $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetVideoEncoderConfigurations: Communication error');
            }
            //var_dump($response);
        } else {
            if (! $filterToken) {
                $resp = $response['Envelope']['Body']['GetVideoEncoderConfigurationsResponse']['Configurations'];
            } else {
                foreach ($response['Envelope']['Body']['GetVideoEncoderConfigurationsResponse']['Configurations'] as $resp) {
                    if ($resp['@attributes']['token'] == $filterToken) {
                        break;
                    }
                }
            }

            return $resp;
        }
    }

    /**
     * @param $profileToken
     *
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetVideoEncoderConfigurationOptions($profileToken)
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetVideoEncoderConfigurationOptions xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken></GetVideoEncoderConfigurationOptions></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
            '%%PASSWORD%%',
            '%%NONCE%%',
            '%%CREATED%%',
            '%%PROFILETOKEN%%', ],
            [$REQ['USERNAME'],
                $REQ['PASSDIGEST'],
                $REQ['NONCE'],
                $REQ['TIMESTAMP'],
                $profileToken, ],
            $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetVideoEncoderConfigurationOptions: Communication error');
            }
            //var_dump($response);
        } else {
            return $response['Envelope']['Body']['GetVideoEncoderConfigurationOptionsResponse']['Options'];
        }
    }

    /**
     * @param $vec
     *
     * @throws Exception
     */
    public function media_SetVideoEncoderConfiguration($vec)
    {
        $REQ = $this->_makeToken();

        $post_string = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:chan="http://schemas.microsoft.com/ws/2005/02/duplex" xmlns:dom0="http://www.axis.com/2009/event" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:ter="http://www.onvif.org/ver10/error" xmlns:tev="http://www.onvif.org/ver10/events/wsdl" xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl" xmlns:tmd="http://www.onvif.org/ver10/deviceIO/wsdl" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wsa5="http://www.w3.org/2005/08/addressing" xmlns:wsc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" xmlns:wsrfbf="http://docs.oasis-open.org/wsrf/bf-2" xmlns:wsrfr="http://docs.oasis-open.org/wsrf/r-2" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wstop="http://docs.oasis-open.org/wsn/t-1" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xmime="http://tempuri.org/xmime.xsd" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
					<s:Header>
						<wsse:Security s:mustUnderstand="true">
							<wsse:UsernameToken>
								<wsse:Username>%%USERNAME%%</wsse:Username>
								<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</wsse:Password>
								<wsse:Nonce>%%NONCE%%</wsse:Nonce>
								<wsu:Created>%%CREATED%%</wsu:Created>
							</wsse:UsernameToken>
						</wsse:Security>
					</s:Header>
					%%BODY%%
				</s:Envelope>';

        $optConfig = '';

        if (isset($vec['RateControl'])) {
            $optConfig .= "	<tt:RateControl>
						<tt:FrameRateLimit>{$vec['RateControl']['FrameRateLimit']}</tt:FrameRateLimit>
						<tt:EncodingInterval>{$vec['RateControl']['EncodingInterval']}</tt:EncodingInterval>
						<tt:BitrateLimit>{$vec['RateControl']['BitrateLimit']}</tt:BitrateLimit>
					</tt:RateControl>";
        }

        if (isset($vec['MPEG4'])) {
            $optConfig .= "	<tt:MPEG4>
						<tt:GovLength>{$vec['MPEG4']['GovLength']}</tt:GovLength>
						<tt:Mpeg4Profile>{$vec['MPEG4']['Mpeg4Profile']}</tt:H264Profile>
					</tt:MPEG4>";
        }

        if (isset($vec['H264'])) {
            $optConfig .= "	<tt:H264>
						<tt:GovLength>{$vec['H264']['GovLength']}</tt:GovLength>
						<tt:H264Profile>{$vec['H264']['H264Profile']}</tt:H264Profile>
					</tt:H264>";
        }

        // FIXME: Create function array2xml with XML-Namespaces
        $post_string_body = "	<s:Body>
						<trt:SetVideoEncoderConfiguration>
							<trt:Configuration xsi:type=\"tt:VideoEncoderConfiguration\" token=\"{$vec['@attributes']['token']}\">
								<tt:Name>{$vec['Name']}</tt:Name>
								<tt:UseCount>{$vec['UseCount']}</tt:UseCount>
								<tt:Encoding>{$vec['Encoding']}</tt:Encoding>
								<tt:Resolution>
									<tt:Width>{$vec['Resolution']['Width']}</tt:Width>
									<tt:Height>{$vec['Resolution']['Height']}</tt:Height>
								</tt:Resolution>
								<tt:Quality>{$vec['Quality']}</tt:Quality>
								{$optConfig}
								<tt:Multicast>
									<tt:Address>
										<tt:Type>{$vec['Multicast']['Address']['Type']}</tt:Type>
										<tt:IPv4Address>{$vec['Multicast']['Address']['IPv4Address']}</tt:IPv4Address>
									</tt:Address>
									<tt:Port>{$vec['Multicast']['Port']}</tt:Port>
									<tt:TTL>{$vec['Multicast']['TTL']}</tt:TTL>
									<tt:AutoStart>{$vec['Multicast']['AutoStart']}</tt:AutoStart>
								</tt:Multicast>
								<tt:SessionTimeout>{$vec['SessionTimeout']}</tt:SessionTimeout>
							</trt:Configuration>
							<trt:ForcePersistence>true</trt:ForcePersistence>
						</trt:SetVideoEncoderConfiguration>
					</s:Body>";

        $post_string=str_replace(['%%USERNAME%%',
                    '%%PASSWORD%%',
                    '%%NONCE%%',
                    '%%CREATED%%',
                    '%%BODY%%', ],
                    [$REQ['USERNAME'],
                        $REQ['PASSDIGEST'],
                        $REQ['NONCE'],
                        $REQ['TIMESTAMP'],
                        $post_string_body, ],
                    $post_string);

        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('SetVideoEncoderConfiguration: Communication error');
            }
        }
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function media_GetOSDs()
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetOSDs xmlns="http://www.onvif.org/ver10/media/wsdl"></GetOSDs></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
            '%%PASSWORD%%',
            '%%NONCE%%',
            '%%CREATED%%', ],
            [$REQ['USERNAME'],
                $REQ['PASSDIGEST'],
                $REQ['NONCE'],
                $REQ['TIMESTAMP'], ],
            $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetOSDs: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetOSDsResponse']['OSDs'];
        }
    }

    /**
     * @param $OSDToken
     *
     * @throws Exception
     */
    public function media_DeleteOSD($OSDToken)
    {
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><DeleteOSD xmlns="http://www.onvif.org/ver10/media/wsdl"><OSDToken>%%OSDToken%%</OSDToken></DeleteOSD></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
            '%%PASSWORD%%',
            '%%NONCE%%',
            '%%CREATED%%',
            '%%OSDToken%%', ],
            [$REQ['USERNAME'],
                $REQ['PASSDIGEST'],
                $REQ['NONCE'],
                $REQ['TIMESTAMP'],
                $OSDToken, ],
            $post_string);
        if ($this->isFault($response=$this->_send_request($this->mediaUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('DeleteOSD: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_GetPresets($profileToken)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetPresets xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken></GetPresets></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken, ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetPresets: Communication error');
            }
        } else {
            $getpresetsresponse=$response['Envelope']['Body']['GetPresetsResponse']['Preset'];
            $presets           =[];
            foreach ($getpresetsresponse as $preset) {
                $presets[]=['Token'           => $preset['@attributes']['token'],
                                 'Name'       => $preset['Name'],
                                 'PTZPosition'=> $preset['PTZPosition'], ];
            }

            return $presets;
        }
    }

    /**
     * @param $ptzNodeToken
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_GetNode($ptzNodeToken)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetNode xmlns="http://www.onvif.org/ver20/ptz/wsdl"><NodeToken>%%NODETOKEN%%</NodeToken></GetNode></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%NODETOKEN%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $ptzNodeToken, ],
                         $post_string);
        if ($this->isFault($response=$this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GetNode: Communication error');
            }
        } else {
            return $response['Envelope']['Body']['GetNodeResponse'];
        }
    }

    /**
     * @param $profileToken
     * @param $presetToken
     * @param $speed_pantilt_x
     * @param $speed_pantilt_y
     * @param $speed_zoom_x
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_GotoPreset($profileToken, $presetToken, $speed_pantilt_x, $speed_pantilt_y, $speed_zoom_x)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GotoPreset xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><PresetToken>%%PRESETTOKEN%%</PresetToken><Speed><PanTilt x="%%SPEEDPANTILTX%%" y="%%SPEEDPANTILTY%%" xmlns="http://www.onvif.org/ver10/schema"/><Zoom x="%%SPEEDZOOMX%%" xmlns="http://www.onvif.org/ver10/schema"/></Speed></GotoPreset></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%PRESETTOKEN%%',
                   '%%SPEEDPANTILTX%%',
                   '%%SPEEDPANTILTY%%',
                   '%%SPEEDZOOMX%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $presetToken,
                   $speed_pantilt_x,
                   $speed_pantilt_y,
                   $speed_zoom_x, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('GotoPreset: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $presetToken
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_RemovePreset($profileToken, $presetToken)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><RemovePreset xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><PresetToken>%%PRESETTOKEN%%</PresetToken></RemovePreset></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%PRESETTOKEN%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $presetToken, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('RemovePreset: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $presetName
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_SetPreset($profileToken, $presetName)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><SetPreset xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><PresetName>%%PRESETNAME%%</PresetName></SetPreset></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%PRESETNAME%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $presetName, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('SetPreset: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $translation_pantilt_x
     * @param $translation_pantilt_y
     * @param $speed_pantilt_x
     * @param $speed_pantilt_y
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_RelativeMove($profileToken, $translation_pantilt_x, $translation_pantilt_y, $speed_pantilt_x, $speed_pantilt_y)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><RelativeMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><Translation><PanTilt x="%%TRANSLATIONPANTILTX%%" y="%%TRANSLATIONPANTILTY%%" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/></Translation><Speed><PanTilt x="%%SPEEDPANTILTX%%" y="%%SPEEDPANTILTY%%" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace" xmlns="http://www.onvif.org/ver10/schema"/></Speed></RelativeMove></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%TRANSLATIONPANTILTX%%',
                   '%%TRANSLATIONPANTILTY%%',
                   '%%SPEEDPANTILTX%%',
                   '%%SPEEDPANTILTY%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $translation_pantilt_x,
                   $translation_pantilt_y,
                   $speed_pantilt_x,
                   $speed_pantilt_y, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('RelativeMove: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $zoom
     * @param $speedZoom
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_RelativeMoveZoom($profileToken, $zoom, $speedZoom)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><RelativeMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><Translation><Zoom x="%%ZOOM%%" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/></Translation><Speed><Zoom x="%%SPEEDZOOM%%" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace" xmlns="http://www.onvif.org/ver10/schema"/></Speed></RelativeMove></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%SPEEDZOOM%%',
                   '%%ZOOM%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $speedZoom,
                   $zoom, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('RelativeMoveZoom: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $position_pantilt_x
     * @param $position_pantilt_y
     * @param $zoom
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_AbsoluteMove($profileToken, $position_pantilt_x, $position_pantilt_y, $zoom)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><Position><PanTilt x="%%POSITIONPANTILTX%%" y="%%POSITIONPANTILTY%%" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/><Zoom x="%%ZOOM%%" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/></Position></AbsoluteMove></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%POSITIONPANTILTX%%',
                   '%%POSITIONPANTILTY%%',
                   '%%ZOOM%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $position_pantilt_x,
                   $position_pantilt_y,
                   $zoom, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('AbsoluteMove: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $velocity_pantilt_x
     * @param $velocity_pantilt_y
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_ContinuousMove($profileToken, $velocity_pantilt_x, $velocity_pantilt_y)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><Velocity><PanTilt x="%%VELOCITYPANTILTX%%" y="%%VELOCITYPANTILTY%%" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/></Velocity></ContinuousMove></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%VELOCITYPANTILTX%%',
                   '%%VELOCITYPANTILTY%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $velocity_pantilt_x,
                   $velocity_pantilt_y, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('ContinuousMove: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $zoom
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_ContinuousMoveZoom($profileToken, $zoom)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><Velocity><Zoom x="%%ZOOM%%" space="http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace" xmlns="http://www.onvif.org/ver10/schema"/></Velocity></ContinuousMove></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%ZOOM%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $zoom, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('ContinuousMoveZoom: Communication error');
            }
        }
    }

    /**
     * @param $profileToken
     * @param $pantilt
     * @param $zoom
     *
     * @throws Exception
     *
     * @return array
     */
    public function ptz_Stop($profileToken, $pantilt, $zoom)
    {
        if ($this->ptzUri == '') {
            return [];
        }
        $REQ        =$this->_makeToken();
        $post_string='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><UsernameToken><Username>%%USERNAME%%</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">%%PASSWORD%%</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%%NONCE%%</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">%%CREATED%%</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><Stop xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>%%PROFILETOKEN%%</ProfileToken><PanTilt>%%PANTILT%%</PanTilt><Zoom>%%ZOOM%%</Zoom></Stop></s:Body></s:Envelope>';
        $post_string=str_replace(['%%USERNAME%%',
                               '%%PASSWORD%%',
                               '%%NONCE%%',
                               '%%CREATED%%',
                   '%%PROFILETOKEN%%',
                   '%%PANTILT%%',
                   '%%ZOOM%%', ],
                         [$REQ['USERNAME'],
                               $REQ['PASSDIGEST'],
                               $REQ['NONCE'],
                               $REQ['TIMESTAMP'],
                   $profileToken,
                   $pantilt,
                   $zoom, ],
                         $post_string);
        if ($this->isFault($this->_send_request($this->ptzUri, $post_string))) {
            if ($this->breakOnError) {
                throw new Exception('Stop: Communication error');
            }
        }
    }

    /**
     * Internal functions
     *
     * @return array
     */
    private function _makeToken()
    {
        $timestamp=time() - $this->deltatime;

        return $this->_passwordDigest($this->username, $this->password, date('Y-m-d\TH:i:s.000\Z', $timestamp));
    }

    /**
     * @param $capabilities
     *
     * @return array
     */
    private function _getOnvifVersion($capabilities)
    {
        $version=[];
        if (isset($capabilities['Device']['System']['SupportedVersions']['Major'])) {
            // NVT supports a specific onvif version
        $version['major']    =$capabilities['Device']['System']['SupportedVersions']['Major'];
            $version['minor']=$capabilities['Device']['System']['SupportedVersions']['Minor'];
        } else {
            // NVT supports more onvif versions
        $currentma    =0;
            $currentmi=0;
            foreach ($capabilities['Device']['System']['SupportedVersions'] as $cver) {
                if ($cver['Major'] > $currentma) {
                    $currentma=$cver['Major'];
                    $currentmi=$cver['Minor'];
                }
            }
            $version['major']=$currentma;
            $version['minor']=$currentmi;
        }
        $version['media'] =$capabilities['Media']['XAddr'];
        $version['device']=$capabilities['Device']['XAddr'];
        $version['event'] =$capabilities['Events']['XAddr'];
        if (isset($capabilities['PTZ']['XAddr'])) {
            $version['ptz']=$capabilities['PTZ']['XAddr'];
        } else {
            $version['ptz']='';
        }

        return $version;
    }

    /**
     * @param $videoSources
     * @param $profiles
     *
     * @return array
     */
    private function _getActiveSources($videoSources, $profiles)
    {
        $sources=[];

        if (isset($videoSources['@attributes'])) {
            // NVT is a camera
            $sources[0]['sourcetoken']=$videoSources['@attributes']['token'];
            $this->_getProfileData($sources, 0, $profiles);
        } else {
            // NVT is an encoder
            for ($i=0;$i < count($videoSources);$i++) {
                if (strtolower($videoSources[$i]['@attributes']['SignalActive']) == 'true') {
                    $sources[$i]['sourcetoken']=$videoSources[$i]['@attributes']['token'];
                    $this->_getProfileData($sources, $i, $profiles);
                }
            } // for
        }

        return $sources;
    }

    /**
     * @param $sources
     * @param $i
     * @param $profiles
     */
    private function _getProfileData(&$sources, $i, $profiles)
    {
        $inprofile=0;
        for ($y=0; $y < count($profiles); $y++) {
            if ($profiles[$y]['VideoSourceConfiguration']['SourceToken'] == $sources[$i]['sourcetoken']) {
                $sources[$i][$inprofile]['profilename'] =$profiles[$y]['Name'];
                $sources[$i][$inprofile]['profiletoken']=$profiles[$y]['@attributes']['token'];
                if (isset($profiles[$y]['VideoEncoderConfiguration'])) {
                    $sources[$i][$inprofile]['encodername']=$profiles[$y]['VideoEncoderConfiguration']['Name'];
                    $sources[$i][$inprofile]['encoding']   =$profiles[$y]['VideoEncoderConfiguration']['Encoding'];
                    $sources[$i][$inprofile]['width']      =$profiles[$y]['VideoEncoderConfiguration']['Resolution']['Width'];
                    $sources[$i][$inprofile]['height']     =$profiles[$y]['VideoEncoderConfiguration']['Resolution']['Height'];
                    $sources[$i][$inprofile]['fps']        =$profiles[$y]['VideoEncoderConfiguration']['RateControl']['FrameRateLimit'];
                    $sources[$i][$inprofile]['bitrate']    =$profiles[$y]['VideoEncoderConfiguration']['RateControl']['BitrateLimit'];
                }
                if (isset($profiles[$y]['PTZConfiguration'])) {
                    $sources[$i][$inprofile]['ptz']['name']     =$profiles[$y]['PTZConfiguration']['Name'];
                    $sources[$i][$inprofile]['ptz']['nodetoken']=$profiles[$y]['PTZConfiguration']['NodeToken'];
                }
                $inprofile++;
            }
        }
    }

    /**
     * @param $codec
     *
     * @return array
     */
    private function _getCodecEncoders($codec)
    { // 'JPEG', 'MPEG4', 'H264'
        $encoders = [];
        foreach ($this->sources as $ncam => $sCam) {
            $encoders[$ncam] = [];
            foreach ($sCam as $sCamProfile) {
                if (isset($sCamProfile['profiletoken'])) {
                    $profileToken              = $sCamProfile['profiletoken'];
                    $encoderName               = $sCamProfile['encodername'];
                    $VideoEncoderConfiguration = $this->media_GetVideoEncoderConfigurationOptions($profileToken);

                    if (isset($VideoEncoderConfiguration[$codec])) {
                        $enc                 = [];
                        $enc['Name']         = $encoderName;
                        $enc['profileToken'] = $profileToken;
                        $enc['QualityRange'] = $VideoEncoderConfiguration['QualityRange'];
                        $encoders[$ncam][]   = array_merge($enc, $VideoEncoderConfiguration[$codec]);
                    }
                }
            }
        }

        return $encoders;
    }

    /**
     * @param $response
     *
     * @return array|mixed
     */
    private function _xml2array($response)
    {
        $sxe     = new SimpleXMLElement($response);
        $dom_sxe = dom_import_simplexml($sxe);
        $dom     = new DOMDocument('1.0');
        $dom_sxe = $dom->importNode($dom_sxe, true);
        $dom_sxe = $dom->appendChild($dom_sxe);
        $element = $dom->childNodes->item(0);
        foreach ($sxe->getDocNamespaces() as $name => $uri) {
            $element->removeAttributeNS($uri, $name);
        }
        $xmldata=$dom->saveXML();
        $xmldata=substr($xmldata, strpos($xmldata, '<Envelope>'));
        $xmldata=substr($xmldata, 0, strpos($xmldata, '</Envelope>') + strlen('</Envelope>'));
        $xml    =simplexml_load_string($xmldata);
        $data   =json_decode(json_encode((array) $xml), 1);
        $data   =[$xml->getName()=>$data];

        return $data;
    }

    /**
     * @param $username
     * @param $password
     * @param string $timestamp
     * @param string $nonce
     *
     * @return array
     */
    private function _passwordDigest($username, $password, $timestamp = 'default', $nonce = 'default')
    {
        if ($timestamp == 'default') {
            $timestamp=date('Y-m-d\TH:i:s.000\Z');
        }
        if ($nonce == 'default') {
            $nonce=mt_rand();
        }
        $REQ        =[];
        $passdigest = base64_encode(pack('H*', sha1(pack('H*', $nonce) . pack('a*', $timestamp) . pack('a*', $password))));
        //$passdigest=base64_encode(sha1($nonce.$timestamp.$password,true)); // alternative
        $REQ['USERNAME']  =$username;
        $REQ['PASSDIGEST']=$passdigest;
        $REQ['NONCE']     =base64_encode(pack('H*', $nonce));
        //$REQ['NONCE']=base64_encode($nonce); // alternative
        $REQ['TIMESTAMP']=$timestamp;

        return $REQ;
    }

    /**
     * @param $url
     * @param $post_string
     *
     * @return array|mixed|string
     */
    private function _send_request($url, $post_string)
    {
        $soap_do = curl_init();
        curl_setopt($soap_do, CURLOPT_URL, $url);
        if ($this->proxyHost != '' && $this->proxyPort != '') {
            curl_setopt($soap_do, CURLOPT_PROXY, $this->proxyHost);
            curl_setopt($soap_do, CURLOPT_PROXYPORT, $this->proxyPort);
            if ($this->proxyUsername != '' && $this->proxyPassword != '') {
                curl_setopt($soap_do, CURLOPT_PROXYUSERPWD, $this->proxyUsername . ':' . $this->proxyPassword);
            }
        }
        curl_setopt($soap_do, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($soap_do, CURLOPT_TIMEOUT, 10);
        curl_setopt($soap_do, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($soap_do, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($soap_do, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($soap_do, CURLOPT_POST, true);
        curl_setopt($soap_do, CURLOPT_POSTFIELDS, $post_string);
        curl_setopt($soap_do, CURLOPT_HTTPHEADER, ['Content-Type: text/xml; charset=utf-8', 'Content-Length: ' . strlen($post_string) ]);
        //curl_setopt($soap_do, CURLOPT_USERPWD, $user . ":" . $password); // HTTP authentication
        if (($result = curl_exec($soap_do)) === false) {
            $err               = curl_error($soap_do);
            $this->lastResponse=['Fault'=>$err];
        } else {
            $this->lastResponse=$this->_xml2array($result);
        }

        return $this->lastResponse;
    }
}
