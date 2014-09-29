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


/********************* AUTH PLUGIN ****************************************/
static int otp_auth_interface(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  unsigned char *pkt;
  int pkt_len;
  /* CHECK BRUTE FORCE, IF BRUTE FORCE CONDITION DON'T ALLOW LOGIN */
  
  
  /* send a password question */
  if (vio->write_packet(vio,
                        (const unsigned char *) PASSWORD_QUESTION "Password, please:",
                        18))
    return CR_ERROR;

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
    /* MUST CHECK HOW NULL PASSWORD WORKS */
    /* INCREASE BRUTE FORCE COUNTER */
    return CR_ERROR;

  info->password_used= PASSWORD_USED_YES;

  /* fail if the password is wrong */
  // check with mysql.users table
  if (strcmp((const char *) pkt, info->auth_string))
    /* INCREASE BRUTE FORCE COUNTER */
    return CR_ERROR;

  /* send otp question */
  if (vio->write_packet(vio,
                        (const unsigned char *) LAST_QUESTION "OTP:", /* INCLUDE OTP TYPE? */
                        5))
    return CR_ERROR;

  /* read the answer */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
    /* INCREASE BRUTE FORCE COUNTER */
    return CR_ERROR;

  /* check the reply */
  
/*
	CREATE TABLE otp_user(
		USER VARCHAR(255) NOT NULL DEFAULT '' COMMENT='USER FROM MYSQL.USER TABLE,MUST CHECK IF WE NEED INCLUDE HOST HERE',
		TYPE ENUM('S/KEY','TOTP','HOTP') NOT NULL DEFAULT 'TOTP' COMMENT='OTP TYPE',
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

  // (1) CHECK IF OTP IS OK
  
  // (2) OK AND ONLY ONE LOGIN, CHECK LAST OTP = CURRENT OTP => (LOGIN)
  
  // (3) IF OK AND NO ONLY ONE LOGIN => (LOGIN)
  
  // (4) WRONG OTP CHECK IF WE SHOULD TRY AGAIN WITH TIME SKEW OR COUNTER SKEW (COUNTER_TIME_SKEW) IF TRUE, TRY AGAIN (1)
  
  // (5) WRONG OTP, INCREMENT BRUTE FORCE ATTACK COUNTER => DON'T ALLOW LOGIN
  
  // (LOGIN) SYNC COUNTER IF USING SKEY/HOTP
  
  return strcmp((const char *) pkt, "yes, of course") ? CR_ERROR : CR_OK;
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
        strmov(message,"Usage: GET_OTP( <user_name> )");
        return 1;
    }
    if (args->arg_count == 1) {
        // one specific user OTP
	// check permission (GRANT)
        args->arg_type[0] = STRING_RESULT;
    } else {
	// current user OTP
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


