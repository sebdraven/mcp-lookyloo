// lk_submit with wait: submission, bounded polling of /json/<uuid>/status (SPEC §2.5, §5.1).
// Status codes from lacuscore 1.12.0 CaptureStatus, as pinned by Lookyloo 1.27.0, and seen on the development instance.
module capture_lifecycle {
  type Status = Unknown | Queued | Done | Ongoing
  type Phase = Idle | Waiting | Finished
  type Result = NoResult | Submitted | RDone | RUnknown | RTimedOut

  pure val WAIT_TIMEOUT = 12
  pure val POLL_INTERVAL = 4
  pure val MAX_UNKNOWN = 3
  pure val MAX_POLLS = WAIT_TIMEOUT / POLL_INTERVAL + 1

  pure def code(s: Status): int = match s {
    | Unknown => -1
    | Queued => 0
    | Done => 1
    | Ongoing => 2
  }

  var phase: Phase
  var wait: bool
  var elapsed: int
  var polls: int
  var unknownStreak: int
  var observed: List[Status]
  var result: Result

  action init = all {
    phase' = Idle,
    wait' = false,
    elapsed' = 0,
    polls' = 0,
    unknownStreak' = 0,
    observed' = [],
    result' = NoResult,
  }

  action submit(w: bool): bool = all {
    phase == Idle,
    wait' = w,
    elapsed' = 0,
    polls' = 0,
    unknownStreak' = 0,
    observed' = [],
    if (w) all { phase' = Waiting, result' = NoResult }
    else all { phase' = Finished, result' = Submitted },
  }

  // the instance may answer anything: the client must stay safe whatever it says
  action poll(s: Status): bool = {
    val streak = if (s == Unknown) unknownStreak + 1 else 0
    val p = polls + 1
    all {
      phase == Waiting,
      wait' = wait,
      polls' = p,
      unknownStreak' = streak,
      observed' = observed.append(s),
      if (s == Done) all { phase' = Finished, result' = RDone, elapsed' = elapsed }
      else if (streak >= MAX_UNKNOWN) all { phase' = Finished, result' = RUnknown, elapsed' = elapsed }
      else if (p >= MAX_POLLS) all { phase' = Finished, result' = RTimedOut, elapsed' = elapsed }
      else all { phase' = Waiting, result' = NoResult, elapsed' = elapsed + POLL_INTERVAL },
    }
  }

  action done = all {
    phase == Finished,
    phase' = phase,
    wait' = wait,
    elapsed' = elapsed,
    polls' = polls,
    unknownStreak' = unknownStreak,
    observed' = observed,
    result' = result,
  }

  action step = any {
    { nondet w = Bool.oneOf() submit(w) },
    { nondet s = Set(Unknown, Queued, Done, Ongoing).oneOf() poll(s) },
    done,
  }

  val pollsBounded = polls <= MAX_POLLS

  val alwaysTerminates = phase == Waiting implies polls < MAX_POLLS

  val elapsedBounded = elapsed <= WAIT_TIMEOUT

  val terminalResults = phase == Finished implies (
    if (wait) Set(RDone, RUnknown, RTimedOut).contains(result) else result == Submitted
  )

  val doneOnlyIfObserved = result == RDone implies (observed.length() > 0 and observed[observed.length() - 1] == Done)

  val neverDoneWithoutPoll = result == RDone implies polls > 0

  val unknownStopsAfterThree = and {
    unknownStreak <= MAX_UNKNOWN,
    result == RUnknown implies (
      observed.length() >= MAX_UNKNOWN
        and observed.slice(observed.length() - MAX_UNKNOWN, observed.length()).foldl(true, (acc, s) => acc and s == Unknown)
    ),
  }

  val noWaitNoPoll = not(wait) implies polls == 0

  val allInvariants = and {
    pollsBounded,
    alwaysTerminates,
    elapsedBounded,
    terminalResults,
    doneOnlyIfObserved,
    neverDoneWithoutPoll,
    unknownStopsAfterThree,
    noWaitNoPoll,
  }

  run submitWithoutWaitTest =
    init.then(submit(false)).then(all {
      assert(result == Submitted),
      assert(polls == 0),
      done,
    })

  run ongoingThenDoneTest =
    init.then(submit(true))
      .then(poll(Ongoing))
      .then(poll(Done))
      .then(all {
        assert(result == RDone),
        assert(polls == 2),
        assert(code(observed[1]) == 1),
        done,
      })

  run queuedOngoingDoneTest =
    init.then(submit(true))
      .then(poll(Queued))
      .then(poll(Ongoing))
      .then(poll(Done))
      .then(all { assert(result == RDone), done })

  run persistentUnknownTest =
    init.then(submit(true))
      .then(poll(Unknown))
      .then(poll(Unknown))
      .then(poll(Unknown))
      .then(all {
        assert(result == RUnknown),
        assert(polls == 3),
        done,
      })

  run unknownStreakResetsTest =
    init.then(submit(true))
      .then(poll(Unknown))
      .then(poll(Unknown))
      .then(poll(Queued))
      .then(poll(Unknown))
      .then(all {
        assert(phase == Finished),
        assert(result == RTimedOut),
        assert(polls == MAX_POLLS),
        done,
      })

  run timeoutTest =
    init.then(submit(true))
      .then(poll(Ongoing))
      .then(poll(Ongoing))
      .then(poll(Ongoing))
      .then(poll(Ongoing))
      .then(all {
        assert(result == RTimedOut),
        assert(polls == MAX_POLLS),
        assert(elapsed == WAIT_TIMEOUT),
        done,
      })
}
