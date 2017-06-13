<?php

require './lib/class.ponvif.php';

$onvif = new Ponvif();

$result = $onvif->discover();

echo '<pre>';
print_r($result);
echo '</pre>';
