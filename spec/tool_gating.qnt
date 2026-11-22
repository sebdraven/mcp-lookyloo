// Tool registration by permission level (SPEC §2, §4 flags, §5.2).
module tool_gating {
  type Level = R | S | P | A
  type Flags = { readOnly: bool, allowPush: bool, allowAdmin: bool }

  pure val TOOLS: str -> Level = Map(
    "lk_capture_info" -> R, "lk_capture_status" -> R, "lk_capture_stats" -> R,
    "lk_capture_redirects" -> R, "lk_capture_urls" -> R, "lk_capture_hostnames" -> R,
    "lk_capture_hashes" -> R, "lk_capture_cookies" -> R, "lk_capture_comparables" -> R,
    "lk_capture_modules" -> R, "lk_capture_misp_export" -> R,
    "lk_capture_screenshot" -> R, "lk_capture_data" -> R, "lk_capture_export" -> R,
    "lk_url_info" -> R, "lk_hostname_info" -> R, "lk_hash_info" -> R, "lk_tld_captures" -> R,
    "lk_categories" -> R, "lk_recent_captures" -> R, "lk_compare_captures" -> R, "lk_takedown_info" -> R,
    "lk_devices" -> R, "lk_instance_stats" -> R, "lk_user_config" -> R,
    "lk_submit" -> S, "lk_trigger_modules" -> S,
    "lk_capture_report" -> P, "lk_misp_push" -> P, "lk_upload_capture" -> P,
    "lk_admin_hide" -> A, "lk_admin_rebuild" -> A, "lk_admin_remove" -> A,
    "lk_admin_rebuild_cache" -> A, "lk_admin_rebuild_all" -> A
  )

  pure val ALL_FLAGS: Set[Flags] = tuples(Bool, Bool, Bool).map(t => { readOnly: t._1, allowPush: t._2, allowAdmin: t._3 })

  pure def allowed(l: Level, f: Flags): bool = match l {
    | R => true
    | S => not(f.readOnly)
    | P => not(f.readOnly) and f.allowPush
    | A => not(f.readOnly) and f.allowAdmin
  }

  pure def expected(f: Flags): Set[str] = TOOLS.keys().filter(t => allowed(TOOLS.get(t), f))

  // f1 grants no more than f2
  pure def leq(f1: Flags, f2: Flags): bool = and {
    f1.readOnly or not(f2.readOnly),
    not(f1.allowPush) or f2.allowPush,
    not(f1.allowAdmin) or f2.allowAdmin,
  }

  var flags: Flags
  var pending: Set[str]
  var registered: Set[str]
  var autoReportSent: bool

  action init = {
    nondet f = ALL_FLAGS.oneOf()
    all {
      flags' = f,
      pending' = TOOLS.keys(),
      registered' = Set(),
      autoReportSent' = false,
    }
  }

  // Register walks every tool once and keeps the ones the flags allow
  action registerOne = {
    nondet t = pending.oneOf()
    all {
      pending' = pending.exclude(Set(t)),
      registered' = if (allowed(TOOLS.get(t), flags)) registered.union(Set(t)) else registered,
      flags' = flags,
      autoReportSent' = autoReportSent,
    }
  }

  // lk_submit with auto_report makes Lookyloo send an email: a push effect
  action submitWithAutoReport = all {
    pending == Set(),
    registered.contains("lk_submit"),
    flags.allowPush,
    autoReportSent' = true,
    flags' = flags,
    pending' = pending,
    registered' = registered,
  }

  action idle = all {
    pending == Set(),
    flags' = flags,
    pending' = pending,
    registered' = registered,
    autoReportSent' = autoReportSent,
  }

  action step = any {
    all { pending != Set(), registerOne },
    submitWithAutoReport,
    idle,
  }

  def levelOf(t: str): Level = TOOLS.get(t)

  val noPushWithoutFlag = not(flags.allowPush) implies registered.forall(t => levelOf(t) != P)

  val noAdminWithoutFlag = not(flags.allowAdmin) implies registered.forall(t => levelOf(t) != A)

  val readOnlyMeansReadTools = flags.readOnly implies registered.forall(t => levelOf(t) == R)

  val registeredWithinExpected = registered.subseteq(expected(flags))

  val doneMeansExact = pending == Set() implies registered == expected(flags)

  val autoReportNeedsPush = autoReportSent implies (flags.allowPush and not(flags.readOnly))

  pure val monotone = ALL_FLAGS.forall(f1 => ALL_FLAGS.forall(f2 => leq(f1, f2) implies expected(f1).subseteq(expected(f2))))

  val allInvariants = and {
    noPushWithoutFlag,
    noAdminWithoutFlag,
    readOnlyMeansReadTools,
    registeredWithinExpected,
    doneMeansExact,
    autoReportNeedsPush,
    monotone,
  }

  pure val NONE = { readOnly: false, allowPush: false, allowAdmin: false }

  run countsTest = all {
    assert(TOOLS.keys().size() == 35),
    assert(expected(NONE).size() == 27),
    assert(expected({ ...NONE, allowPush: true }).size() == 30),
    assert(expected({ ...NONE, allowAdmin: true }).size() == 32),
    assert(expected({ ...NONE, allowPush: true, allowAdmin: true }).size() == 35),
    assert(expected({ readOnly: true, allowPush: true, allowAdmin: true }).size() == 25),
    assert(monotone),
  }

  action setup(f: Flags): bool = all {
    flags' = f,
    pending' = TOOLS.keys(),
    registered' = Set(),
    autoReportSent' = false,
  }

  action registerAll: bool = all {
    pending' = Set(),
    registered' = registered.union(pending.filter(t => allowed(TOOLS.get(t), flags))),
    flags' = flags,
    autoReportSent' = autoReportSent,
  }

  run defaultFlagsTest =
    setup(NONE).then(registerAll).then(all {
      assert(registered.contains("lk_submit")),
      assert(not(registered.contains("lk_misp_push"))),
      assert(not(registered.contains("lk_admin_remove"))),
      assert(allInvariants),
      idle,
    })

  run readOnlyBeatsEverythingTest =
    setup({ readOnly: true, allowPush: true, allowAdmin: true }).then(registerAll).then(all {
      assert(registered.forall(t => levelOf(t) == R)),
      assert(not(registered.contains("lk_submit"))),
      assert(allInvariants),
      idle,
    })

  run everythingTest =
    setup({ ...NONE, allowPush: true, allowAdmin: true }).then(registerAll).then(all {
      assert(registered == TOOLS.keys()),
      assert(not(registered.contains("lk_get_token"))),
      idle,
    }).then(submitWithAutoReport).then(all { assert(autoReportSent), idle })

  run autoReportRefusedWithoutPushTest =
    setup(NONE).then(registerAll).then(submitWithAutoReport.fail())
}
