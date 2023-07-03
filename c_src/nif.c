/*
%%
%% Copyright 2023 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%
*/

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sched.h>

#include <sys/types.h>
#include <libsysevent.h>
#include <libnvpair.h>

#include "erl_nif.h"

static ErlNifResourceType *listener_rsrc;

typedef struct sysev_listener {
	ErlNifMutex		*sl_mtx;
	int			 sl_teardown;
	evchan_t		*sl_evc;
	char			 sl_chan[MAX_CHNAME_LEN];
	char			 sl_subid[MAX_SUBID_LEN];
	char			 sl_class[MAX_CLASS_LEN];
	ErlNifEnv		*sl_env;
	ERL_NIF_TERM		 sl_msgref;
	ErlNifPid		 sl_owner;
	ErlNifMonitor		 sl_monitor;
} sysev_listener_t;

static void
listener_dtor(ErlNifEnv *env, void *arg)
{
	sysev_listener_t *sl = arg;
	evchan_t *evc;
	char subid[MAX_SUBID_LEN];
	int rc;

	enif_mutex_lock(sl->sl_mtx);
	while (sl->sl_teardown) {
		enif_mutex_unlock(sl->sl_mtx);
		sched_yield();
		enif_mutex_lock(sl->sl_mtx);
	}
	evc = sl->sl_evc;
	strlcpy(sl->sl_subid, subid, sizeof (subid));
	sl->sl_teardown = 1;
	enif_mutex_unlock(sl->sl_mtx);

	if (evc == NULL)
		goto free;

	rc = sysevent_evc_unsubscribe(evc, subid);
	(void)rc;

	enif_mutex_lock(sl->sl_mtx);
	if (sl->sl_evc != evc || !sl->sl_teardown)
		abort();

	rc = sysevent_evc_unbind(evc);
	(void)rc;

	sl->sl_evc = NULL;
	bzero(sl->sl_subid, sizeof (sl->sl_subid));
	sl->sl_teardown = 0;
	enif_mutex_unlock(sl->sl_mtx);

free:
	enif_mutex_destroy(sl->sl_mtx);
	sl->sl_mtx = NULL;
	enif_free_env(sl->sl_env);
	sl->sl_env = NULL;
}

static void
listener_mon_down(ErlNifEnv *env, void *arg, ErlNifPid *pid, ErlNifMonitor *mon)
{
	sysev_listener_t *sl = arg;
	evchan_t *evc;
	char subid[MAX_SUBID_LEN];
	int rc;

	enif_mutex_lock(sl->sl_mtx);
	while (sl->sl_teardown) {
		enif_mutex_unlock(sl->sl_mtx);
		sched_yield();
		enif_mutex_lock(sl->sl_mtx);
	}
	evc = sl->sl_evc;
	strlcpy(sl->sl_subid, subid, sizeof (subid));
	sl->sl_teardown = 1;
	enif_mutex_unlock(sl->sl_mtx);

	if (evc == NULL)
		return;

	rc = sysevent_evc_unsubscribe(evc, subid);
	(void)rc;

	enif_mutex_lock(sl->sl_mtx);
	if (sl->sl_evc != evc || !sl->sl_teardown)
		abort();

	rc = sysevent_evc_unbind(evc);
	(void)rc;

	sl->sl_evc = NULL;
	bzero(sl->sl_subid, sizeof (sl->sl_subid));
	sl->sl_teardown = 0;
	enif_mutex_unlock(sl->sl_mtx);
}

static ErlNifResourceTypeInit listener_rsrc_ops = {
	.dtor = listener_dtor,
	.down = listener_mon_down
};

static ERL_NIF_TERM
enif_make_binstr(ErlNifEnv *env, const char *cstr)
{
	ErlNifBinary bin;
	enif_alloc_binary(strlen(cstr), &bin);
	bcopy(cstr, bin.data, bin.size);
	return (enif_make_binary(env, &bin));
}

static void nvlist_to_map(ErlNifEnv *env, ERL_NIF_TERM *map0, nvlist_t *nvl);

static void
nvpair_to_map(ErlNifEnv *env, ERL_NIF_TERM *map0, nvpair_t *nvp)
{
	ERL_NIF_TERM k, v;
	uchar_t byte;
	int8_t i8;
	uint8_t u8;
	int16_t i16;
	uint16_t u16;
	int32_t i32;
	uint32_t u32;
	int64_t i64;
	uint64_t u64;
	hrtime_t time;
	nvlist_t *nvl;
	char *str;
	int rc;

	switch (nvpair_type(nvp)) {
	case DATA_TYPE_UNKNOWN:
		return;
	case DATA_TYPE_BOOLEAN:
		v = enif_make_tuple2(env, enif_make_atom(env, "boolean"),
		    enif_make_atom(env, "true"));
		break;
	case DATA_TYPE_BYTE:
		rc = nvpair_value_byte(nvp, &byte);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "byte"),
		    enif_make_uint(env, byte));
		break;
	case DATA_TYPE_INT8:
		rc = nvpair_value_int8(nvp, &i8);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "int8"),
		    enif_make_int(env, i8));
		break;
	case DATA_TYPE_UINT8:
		rc = nvpair_value_uint8(nvp, &u8);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "uint8"),
		    enif_make_uint(env, u8));
		break;
	case DATA_TYPE_INT16:
		rc = nvpair_value_int16(nvp, &i16);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "int16"),
		    enif_make_int(env, i16));
		break;
	case DATA_TYPE_UINT16:
		rc = nvpair_value_uint16(nvp, &u16);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "uint16"),
		    enif_make_uint(env, u16));
		break;
	case DATA_TYPE_INT32:
		rc = nvpair_value_int32(nvp, &i32);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "int32"),
		    enif_make_int(env, i32));
		break;
	case DATA_TYPE_UINT32:
		rc = nvpair_value_uint32(nvp, &u32);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "uint32"),
		    enif_make_uint(env, u32));
		break;
	case DATA_TYPE_INT64:
		rc = nvpair_value_int64(nvp, &i64);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "int64"),
		    enif_make_int64(env, i64));
		break;
	case DATA_TYPE_UINT64:
		rc = nvpair_value_uint64(nvp, &u64);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "uint64"),
		    enif_make_uint64(env, u64));
		break;
	case DATA_TYPE_STRING:
		rc = nvpair_value_string(nvp, &str);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "string"),
		    enif_make_binstr(env, str));
		break;
	case DATA_TYPE_NVLIST:
		rc = nvpair_value_nvlist(nvp, &nvl);
		if (rc != 0)
			return;
		v = enif_make_new_map(env);
		nvlist_to_map(env, &v, nvl);
		v = enif_make_tuple2(env, enif_make_atom(env, "nvlist"), v);
		break;
	case DATA_TYPE_HRTIME:
		rc = nvpair_value_hrtime(nvp, &time);
		if (rc != 0)
			return;
		v = enif_make_tuple2(env, enif_make_atom(env, "hrtime"),
		    enif_make_uint64(env, time));
		break;
	default:
		v = enif_make_atom(env, "unknown_type");
	}
	k = enif_make_binstr(env, nvpair_name(nvp));
	enif_make_map_put(env, *map0, k, v, map0);
}

static void
nvlist_to_map(ErlNifEnv *env, ERL_NIF_TERM *map0, nvlist_t *nvl)
{
	nvpair_t *nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL)
		nvpair_to_map(env, map0, nvp);
}

static int
sysevent_handler(sysevent_t *ev, void *arg)
{
	sysev_listener_t *sl = arg;
	ErlNifEnv *env = NULL;
	ERL_NIF_TERM msgref;
	ErlNifPid owner;
	ERL_NIF_TERM map, msg, nvmap;
	ERL_NIF_TERM mapk[4], mapv[4];
	hrtime_t time;
	nvlist_t *nvl;
	int rc;

	enif_mutex_lock(sl->sl_mtx);
	if (sl->sl_teardown) {
		enif_mutex_unlock(sl->sl_mtx);
		goto out;
	}
	owner = sl->sl_owner;
	msgref = sl->sl_msgref;
	env = sl->sl_env;
	sl->sl_env = enif_alloc_env();
	sl->sl_msgref = enif_make_copy(sl->sl_env, msgref);
	enif_mutex_unlock(sl->sl_mtx);

	mapk[0] = enif_make_atom(env, "class");
	mapv[0] = enif_make_binstr(env, sysevent_get_class_name(ev));

	mapk[1] = enif_make_atom(env, "subclass");
	mapv[1] = enif_make_binstr(env, sysevent_get_subclass_name(ev));

	mapk[2] = enif_make_atom(env, "seq");
	mapv[2] = enif_make_uint64(env, sysevent_get_seq(ev));

	mapk[3] = enif_make_atom(env, "time");
	sysevent_get_time(ev, &time);
	mapv[3] = enif_make_uint64(env, time);

	rc = enif_make_map_from_arrays(env, mapk, mapv, 4, &map);
	if (!rc)
		goto out;

	nvmap = enif_make_new_map(env);
	if (sysevent_get_attr_list(ev, &nvl) == 0)
		nvlist_to_map(env, &nvmap, nvl);

	msg = enif_make_tuple4(env, enif_make_atom(env, "sysevent"),
	    msgref, map, nvmap);
	enif_send(NULL, &owner, env, msg);
	enif_free_env(env);
	env = NULL;

out:
	if (env != NULL)
		enif_free_env(env);
	return (0);
}

static ERL_NIF_TERM
enif_make_errno(ErlNifEnv *env, const char *func, int eno)
{
	char buf[256];
	strerror_r(eno, buf, sizeof (buf));
	return (enif_make_tuple2(env, enif_make_atom(env, "error"),
	    enif_make_tuple3(env, enif_make_atom(env, func),
	    enif_make_uint(env, eno),
	    enif_make_string(env, buf, ERL_NIF_LATIN1))));
}

static ERL_NIF_TERM
enif_make_err(ErlNifEnv *env, const char *msg)
{
	return (enif_make_tuple2(env, enif_make_atom(env, "error"),
	    enif_make_atom(env, msg)));
}

static ERL_NIF_TERM
enif_make_err2(ErlNifEnv *env, const char *msg, ERL_NIF_TERM what)
{
	return (enif_make_tuple2(env, enif_make_atom(env, "error"),
	    enif_make_tuple2(env, enif_make_atom(env, msg), what)));
}

static ERL_NIF_TERM
nif_evc_subscribe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	sysev_listener_t *sl;
	ErlNifPid self;
	ERL_NIF_TERM msgref, slr, ret, flag, list;
	int rc, bind_flags = 0;
	const char *class;
	ErlNifBinary bin;
	char atom[32];

	if (argc != 4)
		return (enif_make_badarg(env));

	enif_self(env, &self);
	msgref = enif_make_ref(env);

	sl = enif_alloc_resource(listener_rsrc, sizeof (*sl));
	bzero(sl, sizeof (*sl));
	sl->sl_mtx = enif_mutex_create("evc_listener");
	enif_mutex_lock(sl->sl_mtx);
	sl->sl_env = enif_alloc_env();
	sl->sl_owner = self;
	sl->sl_msgref = enif_make_copy(sl->sl_env, msgref);

	if (!enif_inspect_iolist_as_binary(env, argv[0], &bin)) {
		ret = enif_make_err(env, "bad_chan_name");
		goto error;
	}
	if (bin.size < 1 || bin.size >= MAX_CHNAME_LEN) {
		ret = enif_make_err(env, "chan_name_length");
		goto error;
	}
	bcopy(bin.data, sl->sl_chan, bin.size);

	list = argv[1];
	if (!enif_is_list(env, list)) {
		ret = enif_make_err(env, "bad_bind_flags");
		goto error;
	}
	while (enif_get_list_cell(env, list, &flag, &list)) {
		if (!enif_get_atom(env, flag, atom, sizeof (atom),
		    ERL_NIF_LATIN1)) {
			ret = enif_make_err2(env, "bad_bind_flag", flag);
			goto error;
		}
		if (strcmp(atom, "create") == 0) {
			bind_flags |= EVCH_CREAT;
		} else if (strcmp(atom, "hold_pending") == 0) {
			bind_flags |= EVCH_HOLD_PEND;
		} else if (strcmp(atom, "hold_pending_indefinitely") == 0) {
			bind_flags |= EVCH_HOLD_PEND_INDEF;
		} else {
			ret = enif_make_err2(env, "unknown_bind_flag", flag);
			goto error;
		}
	}

	if (!enif_inspect_iolist_as_binary(env, argv[2], &bin)) {
		ret = enif_make_err(env, "bad_subid");
		goto error;
	}
	if (bin.size < 1 || bin.size >= MAX_SUBID_LEN) {
		ret = enif_make_err(env, "subid_length");
		goto error;
	}
	bcopy(bin.data, sl->sl_subid, bin.size);

	if (enif_inspect_iolist_as_binary(env, argv[3], &bin)) {
		if (bin.size < 1 || bin.size >= MAX_CLASS_LEN) {
			ret = enif_make_err(env, "class_length");
			goto error;
		}
		bcopy(bin.data, sl->sl_class, bin.size);
		class = sl->sl_class;
	} else if (enif_get_atom(env, argv[3], atom, sizeof (atom),
	    ERL_NIF_LATIN1)) {
	    	if (strcmp(atom, "all") == 0) {
			class = EC_ALL;
		} else {
			ret = enif_make_err2(env, "bad_class", argv[3]);
			goto error;
		}
	} else {
		ret = enif_make_err(env, "bad_class");
		goto error;
	}

	rc = sysevent_evc_bind(sl->sl_chan, &sl->sl_evc, bind_flags);
	if (rc != 0) {
		ret = enif_make_errno(env, "sysevent_evc_bind", errno);
		goto error;
	}

	rc = sysevent_evc_subscribe(sl->sl_evc, sl->sl_subid, class,
	   sysevent_handler, sl, 0);
	if (rc != 0) {
		sysevent_evc_unbind(sl->sl_evc);
		sl->sl_evc = NULL;
		ret = enif_make_errno(env, "sysevent_evc_subscribe", errno);
		goto error;
	}

	enif_monitor_process(env, sl, &self, &sl->sl_monitor);

	slr = enif_make_resource(env, sl);
	enif_release_resource(sl);

	enif_mutex_unlock(sl->sl_mtx);

	return (enif_make_tuple3(env, enif_make_atom(env, "ok"),
	    slr, msgref));
error:
	enif_mutex_unlock(sl->sl_mtx);
	enif_release_resource(sl);
	return (ret);
}

static ERL_NIF_TERM
nif_evc_unsubscribe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	sysev_listener_t *sl;
	evchan_t *evc;
	char subid[MAX_SUBID_LEN];
	int rc;

	if (argc != 1)
		return (enif_make_badarg(env));

	if (!enif_get_resource(env, argv[0], listener_rsrc, (void **)&sl))
		return (enif_make_badarg(env));

	/*
	 * sysevent_evc_unsubscribe will drain all outstanding door upcalls
	 * for the subscription, meaning we have to drop the sl_mtx when we
	 * call it (or else the event handlers will block up and never finish).
	 *
	 * We set the sl_teardown flag to let those know to exit early and not
	 * send any messages. We also use this to guard against racing
	 * ourselves here.
	 */
	enif_mutex_lock(sl->sl_mtx);
	if (sl->sl_teardown) {
		enif_mutex_unlock(sl->sl_mtx);
		return (enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_atom(env, "busy")));
	}
	evc = sl->sl_evc;
	strlcpy(sl->sl_subid, subid, sizeof (subid));
	sl->sl_teardown = 1;
	enif_mutex_unlock(sl->sl_mtx);

	if (evc == NULL) {
		return (enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_atom(env, "not_subscribed")));
	}

	rc = sysevent_evc_unsubscribe(evc, subid);
	if (rc != 0) {
		return (enif_make_errno(env, "sysevent_evc_unsubscribe",
		    errno));
	}

	enif_mutex_lock(sl->sl_mtx);
	if (sl->sl_evc != evc || !sl->sl_teardown)
		abort();

	rc = sysevent_evc_unbind(evc);
	if (rc != 0) {
		enif_mutex_unlock(sl->sl_mtx);
		return (enif_make_errno(env, "sysevent_evc_unbind", errno));
	}

	sl->sl_evc = NULL;
	bzero(sl->sl_subid, sizeof (sl->sl_subid));
	sl->sl_teardown = 0;
	enif_mutex_unlock(sl->sl_mtx);

	return (enif_make_atom(env, "ok"));
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	listener_rsrc = enif_open_resource_type_x(env, "sysev_listener",
	    &listener_rsrc_ops, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
	    NULL);
	return (0);
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{
	{ "evc_subscribe", 4,	nif_evc_subscribe },
	{ "evc_unsubscribe", 1,	nif_evc_unsubscribe }
};

ERL_NIF_INIT(esysevent, nif_funcs, load_cb, NULL, NULL, unload_cb)
