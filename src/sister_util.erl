-module(sister_util).

%% API
-export([ensure_deps/1,
         ensure_started/1,
         foldl_bytes/3,
         iolist_to_string/1,
         percent_encode/1,
         percent_encode/2,
         unix_timestamp/0,
         unix_timestamp/1]).


%% =============================================================================
%% Types
%% =============================================================================
-export_type [datetime/0,
              byte_folder/1].

%% Types
-type io() :: iolist() | binary().

-type date() :: calendar:date().
-type time() :: calendar:time().

-type datetime() :: {date(), time()}.

-type folder(T,   Acc) :: fun((T, Acc) -> Acc).
-type byte_folder(Acc) :: folder(byte(),  Acc).


%% =============================================================================
%% API Functions
%% =============================================================================

-spec ensure_deps(atom()) -> ok.
ensure_deps(App) ->
    ensure_loaded(App),
    {ok, Deps} = application:get_key(App, applications),
    lists:foreach(fun ensure_started/1, Deps),
    ok.

-spec ensure_started(atom()) -> ok.
ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

-spec foldl_bytes(byte_folder(Acc), Acc, io()) -> Acc.
foldl_bytes(Fun, Acc, Binary) when is_binary(Binary) ->
    foldl_binary_bytes(Fun, Acc, Binary);
foldl_bytes(Fun, Acc, IoList) when is_list(IoList) ->
    foldl_iolist_bytes(Fun, Acc, IoList).

-spec iolist_to_string(iolist()) -> string().
iolist_to_string(IoList) ->
    Binary = iolist_to_binary(IoList),
    binary_to_list(Binary).

-spec percent_encode(io()) -> binary().
percent_encode(Io) ->
    percent_encode(Io, <<>>).

-spec percent_encode(io(), binary()) -> binary().
percent_encode(Io, Acc) ->
    Fun = fun percent_encode_byte/2,
    foldl_bytes(Fun, Acc, Io).

-spec unix_timestamp() -> integer().
unix_timestamp() ->
    DateTime = calendar:universal_time(),
    unix_timestamp(DateTime).

-spec unix_timestamp(datetime()) -> integer().
unix_timestamp(DateTime) ->
    unix_seconds(DateTime) - unix_epoch().


%% =============================================================================
%% Private Functions
%% =============================================================================

-spec ensure_loaded(atom()) -> ok.
ensure_loaded(App) ->
    case application:load(App) of
        ok ->
            ok;
        {error, {already_loaded, App}} ->
            ok
    end.

-spec foldl_binary_bytes(byte_folder(Acc), Acc, binary()) -> Acc.
foldl_binary_bytes(Fun, Acc, <<C:8, Rest/binary>>) ->
    foldl_binary_bytes(Fun, Fun(C, Acc), Rest);
foldl_binary_bytes(  _, Acc, <<>>) -> Acc.

-spec foldl_iolist_bytes(byte_folder(Acc), Acc, iolist()) -> Acc.
foldl_iolist_bytes(Fun, Acc, [Byte|Rest]) when 0 =< Byte, Byte =< 255 ->
    foldl_iolist_bytes(Fun, Fun(Byte, Acc), Rest);
foldl_iolist_bytes(Fun, Acc, [Other|Rest]) ->
    foldl_iolist_bytes(Fun, foldl_bytes(Fun, Acc, Other), Rest);
foldl_iolist_bytes(  _, Acc, []) -> Acc.

-type digit()     :: 16#30..16#39.
-type hex_digit() :: digit() | 16#41..16#46.
-spec hex(16#0..16#F) -> hex_digit().
hex(C) when C > 9 -> $A + C - 10;
hex(C)            -> $0 + C.

-spec percent_encode_byte(byte(), binary()) -> binary().
percent_encode_byte(C, Acc)
  when $0 =< C, C =< $9;
       $a =< C, C =< $z;
       $A =< C, C =< $Z;
       $- == C; C == $.;
       $_ == C; C == $~ ->
    <<Acc/binary, C>>;
percent_encode_byte(C, Acc) ->
    HexA = hex(C band 16#F0 bsr 4),
    HexB = hex(C band 16#0F),
    <<Acc/binary, $%, HexA, HexB>>.

-define(UNIX_EPOCH_DATE,     {1970, 1, 1}).
-define(UNIX_EPOCH_TIME,     {00, 00, 00}).
-define(UNIX_EPOCH_DATETIME, {?UNIX_EPOCH_DATE, ?UNIX_EPOCH_TIME}).

-spec unix_epoch() -> integer().
unix_epoch() ->
    unix_seconds(?UNIX_EPOCH_DATETIME).

-spec unix_seconds(datetime()) -> integer().
unix_seconds(DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime).
