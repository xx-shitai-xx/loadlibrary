#!/usr/bin/php
<?php

$file = file_get_contents('graalengine.map');
$lines = explode("\n", $file);
$data = "";
$last_addr = 0;
function addLine($text){
	global $data;
	$data .= $text;
	$data .= "\n";
};
$i = 0;
foreach ($lines as $line) {

	$func = explode("       ", $line);




	//print( $func[0] . "\n" );

	$addr = explode(":", $func[0]);
	$addr = "0x1" . substr($addr[1],1);
	//print(hexdec("0x00001000"). "\n");
	//print("0x".dechex(4096+hexdec($addr))."\n");


	$address = 4096+hexdec($addr);
	if ($last_addr != 0) {
		$size = $address - $last_addr - 1;
		addLine('size = 0x'.dechex($size));
		addLine('');
	}

	$last_addr = $address;
	addLine( '[[func]]' );
    addLine( 'name = "'.$func[1].'"' );
	addLine( 'addr = 0x' . dechex($address) );

	$i++;

}

print('# Number of functions: ' . $i ."\n");
print($data);