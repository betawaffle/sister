APP := sister
ERL ?= erl

.PHONY: deps

all: deps
	@rebar compile

deps:
	@rebar get-deps

clean:
	@rebar clean

distclean: clean
	@rebar delete-deps

docs:
	@erl -noshell -run edoc_run application '$(APP)' '"."' '[]'

test: all
	@rebar skip_deps=true eunit app=$(APP)
