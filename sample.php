<?php
// function to verified $token
function getVerifiedPayload($token,$time,$leeway,$ttl,$algorithm,$secret) {
    // supported algorithms
    $algorithms = array('HS256'=>'sha256','HS384'=>'sha384','HS512'=>'sha512');
    if (!isset($algorithms[$algorithm])) return false;
    $hmac = $algorithms[$algorithm];
    $token = explode('.',$token);
    if (count($token)<3) return false;
    $header = json_decode(base64_decode(strtr($token[0],'-_','+/')),true);
    if (!$secret) return false;
    if ($header['typ']!='JWT') return false;
    if ($header['alg']!=$algorithm) return false;
    $signature = bin2hex(base64_decode(strtr($token[2],'-_','+/')));
    if ($signature!=hash_hmac($hmac,"$token[0].$token[1]",$secret)) return false;
    $payloads = json_decode(base64_decode(strtr($token[1],'-_','+/')),true);
    if (!$payloads) return false;
    if (isset($payloads['nbf']) && $time+$leeway<$payloads['nbf']) return false;
    if (isset($payloads['iat']) && $time+$leeway<$payloads['iat']) return false;
    if (isset($payloads['exp']) && $time-$leeway>$payloads['exp']) return false;
    if (isset($payloads['iat']) && !isset($payloads['exp'])) {
        if ($time-$leeway>$payloads['iat']+$ttl) return false;
    }
    return $payloads;
}

// function to generate token
function generateToken($payloads,$time,$ttl,$algorithm,$secret) {
    $algorithms = array('HS256'=>'sha256','HS384'=>'sha384','HS512'=>'sha512');
    $header = array();
    $header['typ']='JWT';
    $header['alg']=$algorithm;
    $token = array();
    $token[0] = rtrim(strtr(base64_encode(json_encode((object)$header)),'+/','-_'),'=');
    $payloads['iat'] = $time;
    $payloads['exp'] = $time + $ttl;
    $token[1] = rtrim(strtr(base64_encode(json_encode((object)$payloads)),'+/','-_'),'=');
    if (!isset($algorithms[$algorithm])) return false;
    $hmac = $algorithms[$algorithm];
    $signature = hash_hmac($hmac,"$token[0].$token[1]",$secret,true);
    $token[2] = rtrim(strtr(base64_encode($signature),'+/','-_'),'=');
    return implode('.',$token);
}

// jwt configuration
$algorithm = 'HS256';
$secret = 'secret';
$time = time();
$leeway = 5; // seconds
$ttl = 30; // seconds

// payload to pass into jwt token
$payload = array('id'=>'1','name'=>'Hardik Shah','admin'=>true);
// generated encrypted token
$token = generateToken($payload,$time,$ttl,$algorithm,$secret);
// display generated token
echo "$token";

// decrypt token
$payload = getVerifiedPayload($token,$time,$leeway,$ttl,$algorithm,$secret);
// print data get from jwt web token
echo "<br /><pre>";
var_dump($payload);