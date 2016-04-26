# ponvif

Fork of https://github.com/ltoscano/ponvif with WS-Discovery implementation

## Usage

```
<?php

require 'class.ponvif.php';

$onvif = new Ponvif();
$result = $onvif->discover();

print_r($result);
```
