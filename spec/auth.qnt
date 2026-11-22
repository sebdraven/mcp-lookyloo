// Token resolution for the Lookyloo client (SPEC §3, §5.3).
// Only a token is cached; a failed resolution is retried in full on the next call.
module auth {
  type Source = Env | Keychain | GetToken | NoSource
  type Mode = Required | Optional
  // ok: whether get_token would succeed on this attempt; cached: served from the cache; sent: reached HTTP
  type Attempt = { mode: Mode, ok: bool, cached: bool, source: Source, sent: bool, header: bool }

  // what the process environment offers, fixed for the lifetime of a run
  var envSet: bool
  var keychainSet: bool
  var credsSet: bool

  var token: Source
  var getTokenCalls: int
  var getTokenCallsWithToken: int
  var keychainCallsWithToken: int
  var attempts: List[Attempt]

  pure def chain(env: bool, kc: bool, creds: bool, ok: bool): Source =
    if (env) Env
    else if (kc) Keychain
    else if (creds and ok) GetToken
    else NoSource

  action init = {
    nondet e = Bool.oneOf()
    nondet k = Bool.oneOf()
    nondet c = Bool.oneOf()
    all {
      envSet' = e,
      keychainSet' = k,
      credsSet' = c,
      token' = NoSource,
      getTokenCalls' = 0,
      getTokenCallsWithToken' = 0,
      keychainCallsWithToken' = 0,
      attempts' = [],
    }
  }

  // one call through the client; get_token succeeds on this attempt iff ok (a network failure otherwise)
  action call(m: Mode, ok: bool): bool = {
    val cached = token != NoSource
    val t = if (cached) token else chain(envSet, keychainSet, credsSet, ok)
    val askKeychain = not(cached) and not(envSet)
    val askGetToken = not(cached) and not(envSet) and not(keychainSet) and credsSet
    val sent = not(m == Required and t == NoSource)
    all {
      envSet' = envSet,
      keychainSet' = keychainSet,
      credsSet' = credsSet,
      token' = if (t != NoSource) t else token,
      getTokenCalls' = if (askGetToken) getTokenCalls + 1 else getTokenCalls,
      getTokenCallsWithToken' = if (askGetToken and token != NoSource) getTokenCallsWithToken + 1 else getTokenCallsWithToken,
      keychainCallsWithToken' = if (askKeychain and token != NoSource) keychainCallsWithToken + 1 else keychainCallsWithToken,
      attempts' = attempts.append({ mode: m, ok: ok, cached: cached, source: t, sent: sent, header: sent and t != NoSource }),
    }
  }

  action step = {
    nondet m = Set(Required, Optional).oneOf()
    nondet ok = Bool.oneOf()
    call(m, ok)
  }

  // once a token is obtained, get_token and the keychain are never asked again
  val noGetTokenOnceTokenObtained = getTokenCallsWithToken == 0

  val noKeychainOnceTokenObtained = keychainCallsWithToken == 0

  // only a token is cached
  val onlySuccessIsCached = attempts.foldl(true, (acc, a) => acc and (a.cached implies a.source != NoSource))

  // an attempt not served from the cache gets what env, keychain, get_token give now, in that order:
  // an earlier failure never blocks it
  val failureNeverSticks =
    attempts.foldl(true, (acc, a) => acc and (a.cached or a.source == chain(envSet, keychainSet, credsSet, a.ok)))

  val getTokenOnlyAsLastResort =
    getTokenCalls > 0 implies (not(envSet) and not(keychainSet) and credsSet)

  val cachedTokenFollowsPriority = token != NoSource implies token == chain(envSet, keychainSet, credsSet, true)

  val envAlwaysWins = envSet implies (getTokenCalls == 0 and (attempts.length() > 0 implies token == Env))

  val noAuthenticatedCallWithoutHeader =
    attempts.foldl(true, (acc, a) => acc and ((a.sent and a.mode == Required) implies a.header))

  val allInvariants = and {
    noGetTokenOnceTokenObtained,
    noKeychainOnceTokenObtained,
    onlySuccessIsCached,
    failureNeverSticks,
    getTokenOnlyAsLastResort,
    cachedTokenFollowsPriority,
    envAlwaysWins,
    noAuthenticatedCallWithoutHeader,
  }

  pure def sentCount(l: List[Attempt]): int = l.foldl(0, (n, a) => if (a.sent) n + 1 else n)

  action setup(e: bool, k: bool, c: bool): bool = all {
    envSet' = e,
    keychainSet' = k,
    credsSet' = c,
    token' = NoSource,
    getTokenCalls' = 0,
    getTokenCallsWithToken' = 0,
    keychainCallsWithToken' = 0,
    attempts' = [],
  }

  run envWinsTest =
    setup(true, true, true)
      .then(call(Required, true))
      .then(call(Required, false))
      .then(all {
        assert(token == Env),
        assert(getTokenCalls == 0),
        assert(sentCount(attempts) == 2),
        call(Optional, true),
      })

  run keychainFallbackTest =
    setup(false, true, true)
      .then(call(Required, false))
      .then(all {
        assert(token == Keychain),
        assert(getTokenCalls == 0),
        call(Required, false),
      })
      .then(all {
        assert(attempts[1].cached),
        assert(allInvariants),
        call(Optional, true),
      })

  run getTokenOnceObtainedTest =
    setup(false, false, true)
      .then(call(Optional, true))
      .then(call(Required, false))
      .then(call(Required, false))
      .then(all {
        assert(token == GetToken),
        assert(getTokenCalls == 1),
        assert(sentCount(attempts) == 3),
        assert(noAuthenticatedCallWithoutHeader),
        call(Optional, true),
      })

  run getTokenFailureRetriedTest =
    setup(false, false, true)
      .then(call(Required, false))
      .then(all {
        assert(token == NoSource),
        assert(not(attempts[0].sent)),
        assert(getTokenCalls == 1),
        call(Required, true),
      })
      .then(all {
        assert(token == GetToken),
        assert(getTokenCalls == 2),
        assert(attempts[1].sent and attempts[1].header),
        call(Required, false),
      })
      .then(all {
        assert(getTokenCalls == 2),
        assert(attempts[2].cached and attempts[2].header),
        assert(allInvariants),
        call(Optional, true),
      })

  run requiredWithoutTokenErrorsTest =
    setup(false, false, false)
      .then(call(Required, true))
      .then(all {
        assert(not(attempts[0].sent)),
        assert(getTokenCalls == 0),
        call(Optional, true),
      })
      .then(all {
        assert(attempts[1].sent),
        assert(not(attempts[1].header)),
        assert(not(attempts[1].cached)),
        call(Optional, true),
      })
}
