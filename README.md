esysevent
=====

Erlang bindings for illumos system event channels.

Example
-------

```
1> {ok, Hdl, MsgRef} = esysevent:evc_subscribe("com.sun:zones:status", [], "testing", all).
{ok,#Ref<0.2937418369.3205890050.177596>,
    #Ref<0.2937418369.3205758978.177595>}
2> flush().
Shell got {sysevent,#Ref<0.2937418369.3205758978.177595>,
                    #{class => <<"status">>,seq => 172,
                      subclass => <<"change">>,time => 4745966022729317},
                    #{<<"newstate">> => {string,<<"initialized">>},
                      <<"oldstate">> => {string,<<"uninitialized">>},
                      <<"when">> => {uint64,4745966022720511},
                      <<"zoneid">> => {int32,1},
                      <<"zonename">> => {string,<<"testzone">>}}}
3> esysevent:evc_unsubscribe(Hdl).
ok
```

Installing
----------

Available on [hex.pm](https://hex.pm/packages/esysevent)

API docs
--------

Edoc available on the [hexdocs](https://hexdocs.pm/esysevent)
