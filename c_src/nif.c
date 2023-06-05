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

#include <sys/types.h>
#include <sys/list.h>
#include <libsysevent.h>

#include "erl_nif.h"

static ErlNifResourceType *lis_rsrc;

struct sysev_gl {
	ErlNifMutex		*sg_mtx;
	sysevent_handle_t	*sg_hdl;
	avl_tree_t		 sg_subs;
};

static struct sysev_gl sysev_gl;

struct sysev_sub {
	avl_node_t		  ss_entry;
	char			 *ss_class;
	char			**ss_subclasses;
	size_t			  ss_nsubclasses;
	list_t			  ss_listeners;
};

struct sysev_lis {
	list_node_t		 sl_entry;
	ErlNifEnv		*sl_env;
	ERL_NIF_TERM		 sl_msgref;
	ErlNifPid		 sl_owner;
	ErlNifMonitor		 sl_monitor;
};

static int
compare_sysev_subs(const void *x, const void *y)
{
	const struct sysev_sub *a = x, *b = y;
	uint i;
	int cmp;

	if ((cmp = strcmp(a->ss_class, b->ss_class)) != 0)
		return (cmp);

	if (a->ss_nsubclasses < b->ss_nsubclasses)
		return (-1);
	if (a->ss_nsubclasses > b->ss_nsubclasses)
		return (1);

	for (i = 0; i < a->ss_nsubclasses; ++i) {
		cmp = strcmp(a->ss_subclasses[i], b->ss_subclasses[i]);
		if (cmp != 0)
			return (cmp);
	}

	return (0);
}

static void
listener_dtor(ErlNifEnv *env, void *arg)
{
	struct sysev_lis *sl = arg;
}

static void
listener_mon_down(ErlNifEnv *env, void *arg, ErlNifPid *pid, ErlNifMonitor *mon)
{
	struct sysev_lis *sl = arg;
}

static ErlNifResourceTypeInit lis_rsrc_ops = {
	.dtor = hdl_dtor,
	.down = hdl_mon_down
};

static void
sysevent_handler(sysevent_t *ev)
{
}

static ERL_NIF_TERM
enif_make_errno(ErlNifEnv *env, int eno)
{
	char buf[256];
	strerror_r(eno, buf, sizeof (buf));
	return (enif_make_tuple2(env, enif_make_uint(env, eno),
	    enif_make_string(env, buf, ERL_NIF_LATIN1)));
}

static ERL_NIF_TERM
nif_bind_handle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM ret;

	if (argc != 0)
		return (enif_make_badarg(env));

	enif_mutex_lock(sysev_gl.sg_mtx);

	if (sysev_gl.sg_hdl == NULL) {
		ret = enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_atom(env, "not_bound"));
		goto out;
	}

	if (!avl_is_empty(sysev_gl.sg_subs)) {
		ret = enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_atom(env, "busy"));
		goto out;
	}

	sysevent_unbind_handle(sysev_gl.sg_hdl);
	sysev_gl.sg_hdl = NULL;

	ret = enif_make_atom(env, "ok");

out:
	enif_mutex_unlock(sysev_gl.sg_mtx);
	return (ret);
}

static ERL_NIF_TERM
nif_unbind_handle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM ret;

	if (argc != 0)
		return (enif_make_badarg(env));

	enif_mutex_lock(sysev_gl.sg_mtx);

	if (sysev_gl.sg_hdl != NULL) {
		ret = enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_atom(env, "busy"));
		goto out;
	}

	sysev_gl.sg_hdl = sysevent_bind_handle(sysevent_handler);
	if (sysev_gl.sg_hdl == NULL) {
		ret = enif_make_tuple2(env, enif_make_atom(env, "error"),
		    enif_make_errno(env, errno));
		goto out;
	}

	ret = enif_make_atom(env, "ok");

out:
	enif_mutex_unlock(sysev_gl.sg_mtx);
	return (ret);
}

static int
load_cb(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	bzero(&sysev_gl, sizeof (sysev_gl));
	sysev_gl.sg_mtx = enif_mutex_create("sysev_gl");
	avl_create(&sysev_gl.sg_subs, compare_sysev_subs,
	    sizeof (struct sysev_sub), offsetof(struct sysev_sub, ss_entry));
	lis_rsrc = enif_open_resource_type_x(env, "sysev_listener",
	    &lis_rsrc_ops, ERL_NIF_RT_CREATE | ERLNIF_RT_TAKEOVER,
	    NULL);
	return (0);
}

static void
unload_cb(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] =
{
	{ "bind_handle", 0,	nif_bind_handle },
	{ "unbind_handle", 0,	nif_unbind_handle },
};

ERL_NIF_INIT(esysevent_nif, nif_funcs, load_cb, NULL, NULL, unload_cb)
