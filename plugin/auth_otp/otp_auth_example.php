<?php
	/* please create a user at mysql database */
	$LIB		='MYSQL';	// MYSQL, MYSQLI, PDO
	$HOST		='127.0.0.1';
	$HOST_PORT	=3306;		// ONLY FOR PDO
	$USER		='test';
	$PASSWORD	='';
	$DB		='test';
	/* OTP CONFIGURATION HERE: */
	$data=array(
		"tokentype"	=> "HOTP"			, // the token type (HOTP / TOTP)
		"tokenkey"	=> "9732e257c94c9930818d"	, // the token key /* 9732e257c94c9930818d, FROM : https://code.google.com/p/ga4php/source/browse/trunk/unittests/authtest.php */
		"tokentimer"	=> 30				, // the token timer (For totp) and not supported by ga yet             
		"tokencounter"	=> 1				, // the token counter for hotp
		"tokenalgorithm"=> "SHA1"			, // the token algorithm (not supported by ga yet)
		"user"		=> ""				); // a place for implementors to store their own data
	/* end here */
	
/* FUNCTIONS */
require_once('ga4php.php');	/* from: https://code.google.com/p/ga4php/source/browse/trunk/lib/ga4php.php */
require_once('single_ga4.php');
function create_otp(){
	global $data;
	/////////////////////////////
	$OTP=new singleGA();
	$OTP->setCustomData('none', $data);
	$OTP->setUserKey('none', $data['tokenkey']);
	$data = $OTP->internalGetData('none');
	/////////////////////////////
	if($data['tokentype']=='HOTP'){
		$counter = $data["tokencounter"];
	}else{
		/* 
		FROM: http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm
		compute HOTP from TOTP
			1) Calculate C as the number of >>times<< TI has elapsed after T0.
		considering T0 = 0
		*/
		$T0	 = 0;
		$counter = (int)((time()-$T0)/$data["tokentimer"]);
	}
	return $OTP->oath_hotp($data["tokenkey"], $counter);
}
/* TEST */
	if($LIB == 'MYSQL'){
		if (!function_exists('mysql_connect')) {
			die("Function <mysql_connect> doesn't exists, install <mysql> extension\n");
		}
		// create_otp();
		$link = mysql_connect($HOST, $USER, $PASSWORD);
		if (!$link)
			die('Error: ' . mysql_error());
		mysql_close($link);
		unset($link);
	}else if($LIB == 'MYSQLI'){
		if (!function_exists('mysqli_connect')) {
			die("Function <mysqli_connect> doesn't exists, install <mysqli> extension\n");
		}
		// create_otp();
		$link = mysqli_connect($HOST,$USER,$PASSWORD,$DB);
		if (!$link)
			die('Error: ' . mysqli_error($link)); 		
		mysqli_close($link);
		unset($link);
	}else if($LIB == 'PDO'){
		try{
			// create_otp();
			$dbh = new PDO("mysql:host=$HOST;port=$HOST_PORT;dbname=$DB", $USER, $PASSWORD);
		}catch(PDOException $e){
			die('Error: ' . $e->getMessage());
		}
		unset($e,$dbh);
	}else{
		die("Example <$example> not found <MYSQL/MYSQLI/PDO>");
	}
	die("OK");
