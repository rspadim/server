/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:
#ident "$Id$"
#ident "Copyright (c) 2007 Tokutek Inc.  All rights reserved."
#include "test.h"
#include <db.h>
#include <sys/stat.h>

static DB_ENV *env;
static DB *db;
DB_TXN *txn;

static void
test_setup (void) {
    int r;
    r = system("rm -rf " ENVDIR);
    CKERR(r);
    r=toku_os_mkdir(ENVDIR, S_IRWXU+S_IRWXG+S_IRWXO);       CKERR(r);

    r=db_env_create(&env, 0); CKERR(r);
    env->set_errfile(env, stderr);
    r=env->open(env, ENVDIR, DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN|DB_CREATE|DB_PRIVATE, S_IRWXU+S_IRWXG+S_IRWXO); CKERR(r);
    r=db_create(&db, env, 0); CKERR(r);

    r=env->txn_begin(env, 0, &txn, 0); assert(r==0);
    r=db->open(db, txn, "foo.db", 0, DB_BTREE, DB_CREATE, S_IRWXU+S_IRWXG+S_IRWXO); CKERR(r);
    r=txn->commit(txn, 0);    assert(r==0);
}

static void
test_shutdown (void) {
    int r;
    r= db->close(db, 0); CKERR(r);
    r= env->close(env, 0); CKERR(r);
}

static void
doit (void) {
    DBT key,data;
    int r;
    r=env->txn_begin(env, 0, &txn, 0); assert(r==0);
    r=db->put(db, txn, dbt_init(&key, "a", 2), dbt_init(&data, "a", 2), 0);
    r=db->put(db, txn, dbt_init(&key, "b", 2), dbt_init(&data, "b", 2), 0);
    r=db->put(db, txn, dbt_init(&key, "c", 2), dbt_init(&data, "c", 2), 0);
    r=txn->commit(txn, 0);    assert(r==0);
    
    r=env->txn_begin(env, 0, &txn, 0); assert(r==0);
    r=db->del(db, txn, dbt_init(&key, "b", 2),  0); assert(r==0);
    r=txn->commit(txn, 0);    assert(r==0);

    r=env->txn_begin(env, 0, &txn, 0); assert(r==0);    
    DBC *dbc;
    r = db->cursor(db, txn, &dbc, 0);                           assert(r==0);
    memset(&key,  0, sizeof(key));
    memset(&data, 0, sizeof(data));
    r = dbc->c_get(dbc, &key, &data, DB_FIRST);                 assert(r==0);
    assert(strcmp((char*)key.data, "a")==0);
    assert(strcmp((char*)data.data, "a")==0);
    r = dbc->c_get(dbc, &key, &data, DB_NEXT);                  assert(r==0);
    assert(strcmp((char*)key.data, "c")==0);
    assert(strcmp((char*)data.data, "c")==0);
    r = dbc->c_close(dbc);                                      assert(r==0);
    r=txn->commit(txn, 0);    assert(r==0);
}

int
test_main (int argc, char * const argv[]) {
    parse_args(argc, argv);

    test_setup();
    doit();
    test_shutdown();

    return 0;
}