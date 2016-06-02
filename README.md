# ponvif

Fork of https://github.com/ltoscano/ponvif with WS-Discovery implementation plus some code fixes.

ONVIF PHP implementation

This software module can control network video devices with ONVIF protocol (HTTP SOAP requests) and scan network for supported devices via UDP multicast.

## Usage

### Discovery

```
<?php

require 'class.ponvif.php';

$onvif = new Ponvif();
$result = $onvif->discover();

print_r($result);
```

### Discovery options
setDiscoveryTimeout(5) - timeout for device response; default "2"

setDiscoveryBindIp('192.168.1.5') - choose ethernet card for discovery request; default "0.0.0.0"

setDiscoveryHideDuplicates(false) - disable duplicate filtering (some devices may send more than one response); default "true"


### Get media streams

```
<?php

require 'class.ponvif.php';

$onvif = new Ponvif();
$onvif->setUsername('admin');
$onvif->setPassword('password');
$onvif->setIPAddress('192.168.1.108');

try
{
	$onvif->initialize();
	
	$sources = $onvif->getSources();
	$profileToken = $sources[0][0]['profiletoken'];
	$mediaUri = $onvif->media_GetStreamUri($profileToken);
	
	print_r($mediaUri);
}
catch(Exception $e)
{
	
}
```

and more ...

- Get the system date
- Get the system capabilities
- Get the video sources
- Get the existing profiles
- Get the available services
- Get information of the device information
- Get the URI of a stream
- Get the available presets
- Get information of a given node
- Go to a given preset
- Remove a given preset
- Set a given preset
- Perform a relative move
- Perform a relative move and zoom
- Perform an absolute move
- Start a continuous move
- Start a continuous move and zoom
- Stop a move
