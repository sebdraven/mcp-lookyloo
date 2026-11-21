// Token resolution for the Lookyloo client (SPEC §3, §5.3).
module auth {
  type Source = Env | Keychain | GetToken | NoSource
  type Mode = Required | Optional
  type HTTPCall = { mode: Mode, header: bool }

  // what the process environment offers, fixed for the lifetime of a run
  var envSet: bool
  var keychainSet: bool
  var credsSet: bool
  var getTokenOK: bool

  var resolved: bool
  var token: Source
  var getTokenCalls: int
  var keychainCalls: int
  var httpLog: List[HTTPCall]
  var errors: int

  pure def chain(env: bool, kc: bool, creds: bool, ok: bool): Source =
    if (env) Env
    else if (kc) Keychain
    else if (creds and ok) GetToken
    else NoSource

  action init = {
    nondet e = Bool.oneOf()
    nondet k = Bool.oneOf()
    nondet c = Bool.oneOf()
    nondet ok = Bool.oneOf()
    all {
      envSet' = e,
      keychainSet' = k,
      credsSet' = c,
      getTokenOK' = ok,
      resolved' = false,
      token' = NoSource,
      getTokenCalls' = 0,
      keychainCalls' = 0,
      httpLog' = [],
      errors' = 0,
    }
  }

  // one call through the client: resolve once if needed, then send or fail
  action call(m: Mode): bool = {
    val t = if (resolved) token else chain(envSet, keychainSet, credsSet, getTokenOK)
    val askKeychain = not(resolved) and not(envSet)
    val askGetToken = not(resolved) and not(envSet) and not(keychainSet) and credsSet
    all {
      envSet' = envSet,
      keychainSet' = keychainSet,
      credsSet' = credsSet,
      getTokenOK' = getTokenOK,
      resolved' = true,
      token' = t,
      keychainCalls' = if (askKeychain) keychainCalls + 1 else keychainCalls,
      getTokenCalls' = if (askGetToken) getTokenCalls + 1 else getTokenCalls,
      if (m == Required and t == NoSource) all {
        httpLog' = httpLog,
        errors' = errors + 1,
      } else all {
        httpLog' = httpLog.append({ mode: m, header: t != NoSource }),
        errors' = errors,
      },
    }
  }

  action step = {
    nondet m = Set(Required, Optional).oneOf()
    call(m)
  }

  val getTokenAtMostOnce = getTokenCalls <= 1

  val keychainAtMostOnce = keychainCalls <= 1

  val getTokenOnlyAsLastResort =
    getTokenCalls > 0 implies (not(envSet) and not(keychainSet) and credsSet)

  val priorityRespected = resolved implies (token == chain(envSet, keychainSet, credsSet, getTokenOK))

  val envAlwaysWins = (resolved and envSet) implies (token == Env and keychainCalls == 0 and getTokenCalls == 0)

  val noAuthenticatedCallWithoutHeader =
    httpLog.foldl(true, (acc, c) => acc and (c.mode == Required implies c.header))

  val errorsOnlyWithoutToken = errors > 0 implies token == NoSource

  val allInvariants = and {
    getTokenAtMostOnce,
    keychainAtMostOnce,
    getTokenOnlyAsLastResort,
    priorityRespected,
    envAlwaysWins,
    noAuthenticatedCallWithoutHeader,
    errorsOnlyWithoutToken,
  }

  action setup(e: bool, k: bool, c: bool, ok: bool): bool = all {
    envSet' = e,
    keychainSet' = k,
    credsSet' = c,
    getTokenOK' = ok,
    resolved' = false,
    token' = NoSource,
    getTokenCalls' = 0,
    keychainCalls' = 0,
    httpLog' = [],
    errors' = 0,
  }

  run envWinsTest =
    setup(true, true, true, true)
      .then(call(Required))
      .then(call(Required))
      .then(all {
        assert(token == Env),
        assert(keychainCalls == 0),
        assert(getTokenCalls == 0),
        assert(httpLog.length() == 2),
        call(Optional),
      })

  run keychainFallbackTest =
    setup(false, true, true, true)
      .then(call(Required))
      .then(all {
        assert(token == Keychain),
        assert(keychainCalls == 1),
        assert(getTokenCalls == 0),
        call(Required),
      })

  run getTokenOnceTest =
    setup(false, false, true, true)
      .then(call(Optional))
      .then(call(Required))
      .then(call(Required))
      .then(all {
        assert(token == GetToken),
        assert(getTokenCalls == 1),
        assert(httpLog.length() == 3),
        assert(noAuthenticatedCallWithoutHeader),
        call(Optional),
      })

  run getTokenFailureNotRetriedTest =
    setup(false, false, true, false)
      .then(call(Required))
      .then(call(Required))
      .then(all {
        assert(token == NoSource),
        assert(getTokenCalls == 1),
        assert(errors == 2),
        assert(httpLog.length() == 0),
        call(Optional),
      })

  run requiredWithoutTokenErrorsTest =
    setup(false, false, false, false)
      .then(call(Required))
      .then(all {
        assert(errors == 1),
        assert(httpLog.length() == 0),
        assert(getTokenCalls == 0),
        call(Optional),
      })
      .then(all {
        assert(httpLog.length() == 1),
        assert(httpLog[0].header == false),
        call(Optional),
      })
}
