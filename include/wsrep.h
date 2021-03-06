/* Copyright 2014 Codership Oy <http://www.codership.com> & SkySQL Ab

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#ifndef WSREP_INCLUDED
#define WSERP_INCLUDED

#ifdef WITH_WSREP
#define IF_WSREP(A,B) A
#define DBUG_ASSERT_IF_WSREP(A) DBUG_ASSERT(A)

#if !defined(EMBEDDED_LIBRARY)
#define WSREP_FORMAT(my_format)                           \
  ((wsrep_forced_binlog_format != BINLOG_FORMAT_UNSPEC) ? \
   wsrep_forced_binlog_format : my_format)
#else
#define WSREP_FORMAT(my_format) my_format
#endif /* && !EMBEDDED_LIBRARY */

#define WSREP_MYSQL_DB (char *)"mysql"
#define WSREP_TO_ISOLATION_BEGIN(db_, table_, table_list_)                   \
  if (WSREP_ON && WSREP(thd) && wsrep_to_isolation_begin(thd, db_, table_, table_list_)) \
    goto error;

#define WSREP_TO_ISOLATION_END                                              \
  if (WSREP_ON && (WSREP(thd) || (thd && thd->wsrep_exec_mode==TOTAL_ORDER))) \
    wsrep_to_isolation_end(thd);

#define WSREP_DEBUG(...)                                                \
    if (wsrep_debug)     WSREP_LOG(sql_print_information, ##__VA_ARGS__)
#define WSREP_INFO(...)  WSREP_LOG(sql_print_information, ##__VA_ARGS__)
#define WSREP_WARN(...)  WSREP_LOG(sql_print_warning,     ##__VA_ARGS__)
#define WSREP_ERROR(...) WSREP_LOG(sql_print_error,       ##__VA_ARGS__)

#else
#define IF_WSREP(A,B) B
#define DBUG_ASSERT_IF_WSREP(A)
#define WSREP_DEBUG(...)
#define WSREP_INFO(...)
#define WSREP_WARN(...)
#define WSREP_ERROR(...)
#define WSREP_FORMAT(my_format) my_format
#define WSREP_TO_ISOLATION_BEGIN(db_, table_, table_list_)
#define WSREP_TO_ISOLATION_END
#endif

#endif /* WSERP_INCLUDED */
