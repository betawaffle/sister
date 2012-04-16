-module(sister_oauth).

%% API
-export([sign/2]).

%% Imports
-import(sister_util,
        [percent_encode/1,
         percent_encode/2,
         unix_timestamp/0]).

%% EUnit
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Types
-type io()  :: iolist() | binary().
-type url() :: io().

-type method() :: get | post.

-type param()  :: {io(), io()}.
-type params() :: [param()].

-type header()  :: {string(), string()}.
-type headers() :: [header()].

%% Records
-record auth, {consumer_key    :: io(),
               consumer_secret :: io(),
               token           :: io(),
               token_secret    :: io()}.

-record req, {method        :: method(),
              base_url      :: url(),
              headers  = [] :: headers(),
              params   = [] :: params()}.

%% Helpers
-define(ADD_HEADER(Name, Value, Req),
        Req#req{headers = [{Name, Value}|Req#req.headers]}).


%% =============================================================================
%% API Functions
%% =============================================================================

-spec sign(#req{}, #auth{}) -> #req{}.
sign(Req, Auth) ->
    ?ADD_HEADER("Authorization", authorization_header(Req, Auth), Req).


%% =============================================================================
%% Private Functions
%% =============================================================================

-define(OAUTH_VERSION, "1.0").
-define(OAUTH_SIGNATURE_METHOD, "HMAC-SHA1").




-define(OAUTH_PARAMS(Auth, Nonce, Timestamp),
        [{"oauth_consumer_key", Auth#auth.consumer_key},
         {"oauth_nonce", Nonce},
         {"oauth_signature_method", ?OAUTH_SIGNATURE_METHOD},
         {"oauth_timestamp", integer_to_list(Timestamp)},
         {"oauth_token", Auth#auth.token},
         {"oauth_version", ?OAUTH_VERSION}]).

-spec authorization_header(#req{}, #auth{}) -> string().
authorization_header(Req, Auth) ->
    authorization_header(Req, Auth, nonce(), unix_timestamp()).

-spec authorization_header(#req{}, #auth{}, string(), string()) -> string().
authorization_header(Req, Auth, Nonce, Timestamp) ->
    {HeaderT, SigParams} = lists:foldl(fun signature_param_folder/2,
                                       {<<>>, Req#req.params},
                                       ?OAUTH_PARAMS(Auth, Nonce, Timestamp)),
    
    Signature = signature(Req#req.method,
                          Req#req.base_url, SigParams, Auth),

    Header0 = <<"OAuth oauth_signature=\"">>,
    Header1 = percent_encode(Signature, Header0),
    binary_to_list(<<Header1/binary, "\", ",
                     HeaderT/binary>>).

-spec nonce() -> string().
nonce() ->
    Bytes = crypto:rand_bytes(32),
    base64:encode_to_string(Bytes).

-spec signature(method(), url(), params(), #auth{} | binary()) -> binary().
signature(Method, BaseUrl, SigParams, Auth = #auth{}) ->
    SigningKey = signing_key(Auth),
    signature(Method, BaseUrl, SigParams, SigningKey);
signature(Method, BaseUrl, SigParams, SigningKey) ->
    Data = signature_base_string(Method, BaseUrl, SigParams),
    Sig  = crypto:sha_mac(SigningKey, Data),
    base64:encode(Sig).

-spec signature_base_string(method(), url(), params()) -> binary().
signature_base_string(Method, BaseUrl, SigParams) ->
    Sorted = sort_params(SigParams),
    Joined = join_params(Sorted, <<>>),
    IoList = [case Method of
                  post -> "POST";
                  get  -> "GET"
              end, $&,
              percent_encode(BaseUrl), $&,
              percent_encode(Joined)],
    iolist_to_binary(IoList).

-type folded_params() :: {binary(), params()}.
-spec signature_param_folder(param(), folded_params()) -> folded_params().
signature_param_folder({K, V} = Param, {Acc0 = <<>>, Params}) ->
    Acc1 = percent_encode(K,   Acc0),
    Acc2 = percent_encode(V, <<Acc1/binary, $=, $">>),
    {<<Acc2/binary, $">>, [Param|Params]};
signature_param_folder({K, V} = Param, {Acc0, Params}) ->
    Acc1 = percent_encode(K, <<Acc0/binary, ", ">>),
    Acc2 = percent_encode(V, <<Acc1/binary, $=, $">>),
    {<<Acc2/binary, $">>, [Param|Params]}.

-spec signing_key(#auth{}) -> binary().
signing_key(Auth) ->
    signing_key(Auth#auth.consumer_secret, Auth#auth.token_secret).

-spec signing_key(iodata(), iodata()) -> binary().
signing_key(ConsumerSecret, TokenSecret) ->
    iolist_to_binary([ConsumerSecret, $&, TokenSecret]).


%% --- Helpers ---

-spec join_params([{iodata(), iodata()}], binary()) -> binary().
join_params([{K, V}|Rest], Acc) ->
    Acc0 = case Acc of
               <<>> ->   Acc;
               _    -> <<Acc/binary, $&>>
           end,
    Acc1 = percent_encode(K,   Acc0),
    Acc2 = percent_encode(V, <<Acc1/binary, $=>>),
    join_params(Rest, Acc2);
join_params([], Acc) ->
    Acc.

sort_params(Params) ->
    lists:ukeysort(1, Params).


%% =============================================================================
%% Tests
%% =============================================================================

-ifdef(TEST).

%% These are from the Twitter API documentation.
%% See https://dev.twitter.com/docs/auth/creating-signature
-define(TEST_CONSUMER_KEY, "xvz1evFS4wEEPTGEFPHBog").
-define(TEST_CONSUMER_SECRET, "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw").
-define(TEST_METHOD, post).
-define(TEST_NONCE, "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg").
-define(TEST_OAUTH_VERSION, "1.0").
-define(TEST_SIGNATURE_METHOD, "HMAC-SHA1").
-define(TEST_TIMESTAMP, 1318622958).
-define(TEST_TIMESTAMP_STR, integer_to_list(?TEST_TIMESTAMP)).
-define(TEST_TOKEN, "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb").
-define(TEST_TOKEN_SECRET, "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE").
-define(TEST_URL, "https://api.twitter.com/1/statuses/update.json").

-define(TEST_OAUTH_PARAMS,
        [{"oauth_consumer_key",     ?TEST_CONSUMER_KEY},
         {"oauth_nonce",            ?TEST_NONCE},
         {"oauth_signature_method", ?TEST_SIGNATURE_METHOD},
         {"oauth_timestamp",        ?TEST_TIMESTAMP_STR},
         {"oauth_token",            ?TEST_TOKEN},
         {"oauth_version",          ?TEST_OAUTH_VERSION}]).
-define(TEST_PARAMS,
        [{"status", "Hello Ladies + Gentlemen, a signed OAuth request!"},
         {"include_entities", "true"}]).

-define(TEST_AUTH, #auth
        {consumer_key    = ?TEST_CONSUMER_KEY,
         consumer_secret = ?TEST_CONSUMER_SECRET,
         token           = ?TEST_TOKEN,
         token_secret    = ?TEST_TOKEN_SECRET}).
-define(TEST_REQ, #req
        {method   = ?TEST_METHOD,
         base_url = ?TEST_URL,
         headers  = [],
         params   = ?TEST_PARAMS}).

-define(TEST_HEADER,
        "OAuth "
        "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", "
        "oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", "
        "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", "
        "oauth_signature_method=\"HMAC-SHA1\", "
        "oauth_timestamp=\"1318622958\", "
        "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", "
        "oauth_version=\"1.0\"").
-define(TEST_SIGNATURE, "tnnArxj06cWHq44gCs1OSKk/jLY=").
-define(TEST_SIGNATURE_BASE_STRING,
        "POST" "&"
        "https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json" "&"
        "include_entities%3Dtrue%26"
        "oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26"
        "oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26"
        "oauth_signature_method%3DHMAC-SHA1%26"
        "oauth_timestamp%3D1318622958%26"
        "oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26"
        "oauth_version%3D1.0%26"
        "status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signe"
        "d%2520OAuth%2520request%2521").
-define(TEST_SIGNING_KEY,
        "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw" "&"
        "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE").

authorization_header_test() ->
    F = fun authorization_header/4,
    Y = F(?TEST_REQ,
          ?TEST_AUTH,
          ?TEST_NONCE,
          ?TEST_TIMESTAMP),
    Z =   ?TEST_HEADER,

    ?assertMatch(Y, Z).

signature_test() ->
    F = fun signature/4,
    Y = F(?TEST_METHOD,
          ?TEST_URL,
          ?TEST_PARAMS ++ ?TEST_OAUTH_PARAMS,
          ?TEST_AUTH),
    Z = <<?TEST_SIGNATURE>>,

    ?assertMatch(Y, Z).

signature_base_string_test() ->
    F = fun signature_base_string/3,
    Y = F(?TEST_METHOD,
          ?TEST_URL,
          ?TEST_PARAMS ++ ?TEST_OAUTH_PARAMS),
    Z = <<?TEST_SIGNATURE_BASE_STRING>>,

    ?assertMatch(Y, Z).

signing_key_test() ->
    F = fun signing_key/1,
    Y = F(?TEST_AUTH),
    Z = <<?TEST_SIGNING_KEY>>,

    ?assertMatch(Y, Z).

-endif.
