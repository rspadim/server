/* Copyright (C) 2014 Roberto Spadim - Spaempresarial Brazil

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; version 2 of the
    License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA */

// based at dialog_example.c example file
    
#include <mysql/plugin_auth.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mysql/auth_dialog_client.h>

/* TODO: 
   IMPLEMENT TOTP PASSWORD GENERATOR FUNCTION (GENERATE A PASSWORD WITH TIME+KEY+TIME_STEP)
   IMPLEMENT HOTP PASSWORD GENERATOR FUNCTION (GENERATE A PASSWORD WITH COUNTER+KEY)
   IMPLEMENT S/KEY PASSWORD - SAME AS HOTP BUT USING S/KEY LOGIC
*/
function create_totp(); /* 	http://www.nongnu.org/oath-toolkit/ */
function create_hotp(); /* 	http://www.nongnu.org/oath-toolkit/ */
function create_skey(); /* 	ftp://ftp.ntua.gr/mirror/skey/skey/
				http://0x9900.com/blog/2013/08/28/two-factor-authentication-with-ssh-&-s/key-on-openbsd/ */
function create_user_otp(); /* receive user otp table row and select what key should be used */

/********************* AUTH PLUGIN ****************************************/
static int otp_auth_interface(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  int pkt_len;
  /* CHECK BRUTE FORCE, IF BRUTE FORCE CONDITION DON'T ALLOW LOGIN */
  if(user_brute_force_counter>max_user_brute_force_counter && max_user_brute_force_counter>0){
    if(user_brute_force_time>now())
      return CR_ERROR; /* sorry */
    user_brute_force_counter=0;
    reset_brute_force_counter(); /* save to table */
  }
  
  /* send a password question */
  if (vio->write_packet(vio,
                        (const unsigned char *) PASSWORD_QUESTION "Password, please:",
                        18))
    return CR_ERROR; /* ?increase brute force counter? */

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    /* MUST CHECK HOW NULL PASSWORD WORKS */
    /* INCREASE BRUTE FORCE COUNTER */
    increase_brute_force_counter();
    return CR_ERROR;
  }
  info->password_used= PASSWORD_USED_YES;

  /* fail if the password is wrong */
  // check with mysql.users table
  if (strcmp((const char *) pkt, info->auth_string)){
    /* INCREASE BRUTE FORCE COUNTER */
    increase_brute_force_counter();
    return CR_ERROR;
  }

  /* send otp question */
  if (vio->write_packet(vio,
                        (const unsigned char *) LAST_QUESTION "OTP:", /* INCLUDE OTP TYPE? */
                        5))
    return CR_ERROR; /* ?increase brute force counter? */

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0){
    /* INCREASE BRUTE FORCE COUNTER */
    increase_brute_force_counter();
    return CR_ERROR;
  }

  /* check the reply */
  
/*
	CREATE TABLE otp_user(
		USER VARCHAR(255) NOT NULL DEFAULT '' COMMENT='USER FROM MYSQL.USER TABLE,MUST CHECK IF WE NEED INCLUDE HOST HERE',
		TYPE ENUM('S/KEY','TOTP','HOTP') NOT NULL DEFAULT 'TOTP' COMMENT='OTP TYPE',
		  - CHECK http://www.nongnu.org/oath-toolkit/coverage/liboath/usersfile.c.gcov.frameset.html
		  -       THEY  IMPLEMENT SOME HOTP/60/XXXX TO EASIER IMPLEMENT TOTP + 60 STEP SIZE
		SECRET VARCHAR(255) NOT NULL DEFAULT '' COMMENT='BASE32 ENCODED SECRET (TOTP/HOTP)',
		TIME_STEP INT NOT NULL DEFAULT 0,
		COUNTER_TIME_SKEW INT NOT NULL DEFAULT 0 COMMENT='TRY AN OLDER/NEWER OTP PASSWORD, THIS ALLOW TIME SINCRONIZATION OR SYNC A COUNTER',
		BRUTE_FORCE_MAX INT NOT NULL DEFAULT '0' COMMENT='MAX WRONG LOGIN COUNTER',
		BRUTE_FORCE_TIMEOUT DOUBLE NOT NULL DEFAULT '0' COMMENT='WAIT X SECONDS IF GOT BRUTE FORCE ATTACK',
		ONE_ACCESS ENUM('Y','N') NOT NULL DEFAULT 'N' COMMENT='ONLY ALLOW ONE ACCESS PER OTP PASSWORD (TOTP)',
		LAST_ACCESS_OTP DOUBLE NOT NULL DEFAULT '0' COMMENT='LAST LOGIN VALUE TO CALCULATE OTP',
		BRUTE_FORCE_COUNTER INT NOT NULL DEFAULT '0' COMMENT='CURRENT BRUTE FORCE COUNTER',
		BRUTE_FORCE_BLOCK_TIME DOUBLE NOT NULL DEFAULT '0' COMMENT= 'NEXT ALLOWED LOGIN',
		PRIMARY KEY (USER) 
	)
	
	TODO: SHOULD WE USE RULES LIKE OTP, FOR EXAMPLE MANY USERS WITH SAME OTP?
*/


  /* implement well known password check ?*/
  if(well_know_password>0){
    /* check if we got a well_know_password */
    if (wkp_found()){
      remove_current_well_know_password_from_table();
      /*login ok*/
      reset_brute_force_counter();
      // (LOGIN) SYNC COUNTER IF USING SKEY/HOTP
      return CR_OK;
    }
  }
  

  current_time=startup_time=now();
  /* now =>   my_hrtime_t qc_info_now= my_hrtime();   qc_info_now.val  = unix timestamp */
  
  
  current_counter=startup_counter=get_from_otp_table;
  while(1){
    // (1) CHECK IF OTP IS OK
    current_otp_password = create_otp_password(
    	otp_information,
    	current_time,
    	current_counter
    	);
    if (strcmp((const char *) pkt, current_otp_password)){
      // (2) OK AND ONLY ONE LOGIN, CHECK LAST OTP = CURRENT OTP => (LOGIN)
      // (3) IF OK AND NO ONLY ONE LOGIN => (LOGIN)
      if ((one login == 'y' && last_otp_counter_timer==current_otp_counter_time) ||
           one login != 'y'){
        /*login ok*/
        reset_brute_force_counter();
        sync_counter (if using counter_time_skew)
        // (LOGIN) SYNC COUNTER IF USING SKEY/HOTP
        return CR_OK;
      }else if (one login == 'y'){
        increase_brute_force_counter();
        return CR_ERROR;
      }
    }
    // (4) WRONG OTP CHECK IF WE SHOULD TRY AGAIN WITH TIME SKEW OR COUNTER SKEW (COUNTER_TIME_SKEW) IF TRUE, TRY AGAIN (1)
    if(counter_time_skew>0){ /* must check how TOTP/HOTP/SKEY do, there's a RFC */
      change_current_time_counter to a value before or after the startup_time/startup_counter;
      continue; /*try again*/
    }
    // (5) WRONG OTP, INCREMENT BRUTE FORCE ATTACK COUNTER => DON'T ALLOW LOGIN
    // sorry :(
    increase_brute_force_counter();
    return CR_ERROR;
  }
}

static struct st_mysql_auth otp_handler=
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "dialog", /* requires dialog client plugin */
  otp_auth_interface
};

/********************* UDF FUNCTION ****************************************/
/* 
	TODO: include a function to test OTP, 
	for example SELECT GET_OTP('USER') 
	this will allow admin to create user and check if current OTP is ok or not 
	before allowing user to login and start brute force counter
*/
my_bool GET_OTP_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count > 1) {
        strmov(message,"Usage: GET_OTP( <user_name> )"); /* use same primary key as otp table */
        return 1;
    }
    if (args->arg_count == 1) {
        // one specific user OTP
	check permission (GRANT);
        args->arg_type[0] = STRING_RESULT;
    } else {
	// current user OTP 
	/*use the current username*/
    }
/*
    if ( !(initid->ptr = 
        (char *) malloc( sizeof(char) * MAX_IMAGE_SIZE ) ) ) {
        strmov(message, "Couldn't allocate memory!");
        return 1;
    }
    bzero( initid->ptr, sizeof(char) * MAX_IMAGE_SIZE );
*/
    return 0;
}

/* This routine frees the memory allocated */
void GET_OTP_deinit(UDF_INIT *initid) {
    if (initid->ptr)
        free(initid->ptr);
}

/* Return NULL if can't get a OTP */
char *GET_OTP(UDF_INIT *initid, UDF_ARGS *args, char *result,
               unsigned long *length, char *is_null, char *error) {
/*
	strncpy( filename, args->args[0], args->lengths[0] );

	*is_null = 1;	
        return 0;
*/
    with the current user information, return the current OTP password using create_user_otp() function;

    *length = (unsigned long)some_size;
    return initid->ptr;
}


/********************* DECLARATIONS ****************************************/

mysql_declare_plugin(dialog)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &otp_handler,
  "otp_auth",
  "Roberto Spadim - Spaempresarial Brazil",
  "Dialog otp auth plugin",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  NULL,
  NULL,
  0,
}mysql_declare_plugin_end;


