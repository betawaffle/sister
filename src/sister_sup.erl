-module(sister_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    ChildSpecs = [child_pool_sup(), child_pool(1000)],
    {ok, {{one_for_all, 5, 10}, ChildSpecs}}.

%% ===================================================================
%% Private functions
%% ===================================================================

-spec child_pool (pos_integer()) -> supervisor:child_spec().
child_pool(MaxSize) ->
    Mod = sister_pool,
    {Mod, {Mod, start_link, [MaxSize]}, permanent, 5000, worker, [Mod]}.

-spec child_pool_sup () -> supervisor:child_spec().
child_pool_sup() ->
    Mod = sister_pool_sup,
    {Mod, {Mod, start_link, []}, permanent, 5000, supervisor, [Mod]}.
