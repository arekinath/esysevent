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

%% @doc Subscribes to system event channels on illumos
%%
%% This module will only compile and run on illumos/Solaris systems.
%%
%% The most common use of this module is to subscribe to notifications about
%% zone status changes, with channel <code>com.sun:zones:status</code>.
%%
%% Example:
%%
%% <pre>
%% 1> {ok, Hdl, MsgRef} = esysevent:evc_subscribe("com.sun:zones:status", [], "testing", all).
%% {ok,#Ref&lt;0.2937418369.3205890050.177596&gt;,
%%     #Ref&lt;0.2937418369.3205758978.177595&gt;}
%% 2> flush().
%% Shell got {sysevent,#Ref&lt;0.2937418369.3205758978.177595&gt;,
%%                     #{class => &lt;&lt;"status">>,seq => 172,
%%                       subclass => &lt;&lt;"change">>,time => 4745966022729317},
%%                     #{&lt;&lt;"newstate">> => {string,&lt;&lt;"initialized">>},
%%                       &lt;&lt;"oldstate">> => {string,&lt;&lt;"uninitialized">>},
%%                       &lt;&lt;"when">> => {uint64,4745966022720511},
%%                       &lt;&lt;"zoneid">> => {int32,1},
%%                       &lt;&lt;"zonename">> => {string,&lt;&lt;"testzone">>}}}
%% </pre>
-module(esysevent).

-export([
    evc_subscribe/4,
    evc_unsubscribe/1
    ]).

-export_type([
    event_msg/0
    ]).

-on_load(init/0).

try_paths([Last], BaseName) ->
    filename:join([Last, BaseName]);
try_paths([Path | Next], BaseName) ->
    case filelib:is_dir(Path) of
        true ->
            WCard = filename:join([Path, "{lib,}" ++ BaseName ++ ".*"]),
            case filelib:wildcard(WCard) of
                [] -> try_paths(Next, BaseName);
                _ -> filename:join([Path, BaseName])
            end;
        false -> try_paths(Next, BaseName)
    end.

%% @private
init() ->
    Paths0 = [
        filename:join(["..", lib, esysevent, priv]),
        filename:join(["..", priv]),
        filename:join([priv])
    ],
    Paths1 = case code:priv_dir(esysevent) of
        {error, bad_name} -> Paths0;
        Dir -> [Dir | Paths0]
    end,
    SoName = try_paths(Paths1, "esysevent_nif"),
    erlang:load_nif(SoName, 0).

-type errno() :: integer().
%% System errno value

-type func() :: atom().

-type err_result() :: {error, {func(), errno(), string()}} | {error, term()}.

-type channel() :: iolist().
%% String, e.g. com.sun:zones:status

-type bind_flags() :: [create | hold_pending | hold_pending_indefinitely].

-type handle() :: reference().
%% Reference to an EVC handle. Note that if this term gets garbage-collected,
%% the subscription will be automatically cancelled. Subscribers are advised
%% to store it in process state until it is no longer required.

-type msgref() :: reference().
%% Unique reference included in event messages for a given subscription

-type subid() :: iolist().
%% Subscriber name, needs to be unique (include PID or something random)

-type class() :: all | iolist().
%% Class name

-type ev_info() :: #{
    class => binary(),
    subclass => binary(),
    seq => integer(),
    time => integer()
    }.
%% Event metadata, the first term of a {@link event_msg()}

-type nv_int_type() :: byte | int8 | uint8 | int16 | uint16 | int32 | uint32 |
    int64 | uint64.

-type nv_val() :: {boolean, boolean()} | {nv_int_type(), integer()} |
    {string, iolist()} | {array, nv_int_type(), [integer()]} |
    {array, boolean, [boolean()]} | {array, string, [iolist()]} |
    {hrtime, integer()} | {nvlist, nvlist()} | {array, nvlist, [nvlist()]}.

-type nvlist() :: #{binary() => nv_val()}.
%% The general format of an nvlist_t, converted to an Erlang map.

-type ev_attrs() :: nvlist().

-type event_msg() :: {sysevent, msgref(), ev_info(), ev_attrs()}.
%% Format of a message received by an event subscriber.

%% @doc Subscribe to an event channel
%%
%% This will set up the event channel to produce messages targetted at the
%% process which called this function. The {@link msgref()} term returned
%% matches the one included in the messages for this specific subscription.
%% Event messages have the format shown in type {@link event_msg()}.
%%
%% @see channel()
%% @see bind_flags()
%% @see subid()
%% @see class()
%% @see handle()
%% @see event_msg()
-spec evc_subscribe(channel(), bind_flags(), subid(), class()) -> {ok, handle(), msgref()} | err_result().
evc_subscribe(_Channel, _BindFlags, _SubId, _Class) -> error(no_nif).

%% @doc Cancel a subscription to an event channel
%%
%% After this function returns OK, no further new messages for the subscription
%% will be enqueued for the owning process.
%%
%% @see handle()
-spec evc_unsubscribe(handle()) -> ok | err_result().
evc_unsubscribe(_Handle) -> error(no_nif).
