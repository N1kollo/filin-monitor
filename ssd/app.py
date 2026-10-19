"""Startup: main() and the command line."""

import html
import sys
import threading

# every module, in dependency order — importing app loads the whole monitor
from . import (  # noqa: F401
    core,
    webauth,
    storage,
    checks,
    netinventory,
    dhcp,
    ipconflict,
    passive,
    pathdiag,
    wolschedule,
    services,
    recovery,
    wanwatch,
    telegram,
    alerting,
    livestate,
    policy,
    outbox,
    holddown,
    degradation,
    status,
    bot,
    web,
    wifi,
    unifi,
    dahua,
    video,
    update,
    netdiag,
)


def main():
    core.setup_logging()
    core.load_config()
    storage.db_init()
    restored = storage.runtime_restore()
    update.update_note_start()
    livestate.reconcile_state()
    policy.seed_escalations()
    if "unifi_ap_told" not in restored:
        # first run with the AP ledger: APs already down were announced by the
        # previous build — don't re-announce 3-1 after every upgrade
        unifi._UNIFI_AP_TOLD.update(unifi._UNIFI_DOWN)
    if "announced" not in restored:
        # First run with the ledger: a host seeded down from the journal had
        # its "упал" sent by the previous build — let its recovery ring.
        with livestate.STATE_LOCK:
            policy.ANNOUNCED.update(k for k, v in livestate.STATE.items() if v["status"] == "down")
    port = int(core.cfg("web_port", 8081))
    host = core.cfg("web_host", "0.0.0.0")
    print(f"== {core.cfg('app_name')} v{core.__version__} ==")
    print(f"Дашборд:  http://localhost:{port}")
    print(f"Telegram: {'ВКЛ' if telegram.telegram_ready() else 'выкл (настрой в интерфейсе)'}")
    print(f"Пароль:   {'ВКЛ' if webauth.auth_enabled() else 'выкл (включить: python monitor.py --set-password)'}")
    # Bind first: with the port taken (a second copy, UniFi on 8080 once) the
    # old order started 12 threads, sent "🚀 запущен" and then died.
    try:
        server = web.MonitorHTTPServer((host, port), web.Handler)
    except OSError as e:
        msg = f"порт {port} занят ({core.short_err(e)}) — второй экземпляр монитора?"
        print(f"[main] НЕ ЗАПУЩЕН: {msg}")
        if telegram.telegram_ready():
            alerting.emit("system", f"🔴 <b>{html.escape(str(core.cfg('app_name')))}</b> не запустился: "
                           f"{html.escape(msg)}", queue=False)
        sys.exit(1)
    threading.Thread(target=degradation.monitor_loop, daemon=True).start()
    threading.Thread(target=bot.telegram_bot_loop, daemon=True).start()
    threading.Thread(target=degradation.heartbeat_loop, daemon=True).start()
    threading.Thread(target=degradation.degradation_loop, daemon=True).start()
    threading.Thread(target=recovery.wol_schedule_loop, daemon=True).start()
    threading.Thread(target=passive.passive_listen_loop, daemon=True).start()
    threading.Thread(target=wanwatch.wan_loop, daemon=True).start()
    threading.Thread(target=policy.quiet_digest_loop, daemon=True).start()
    threading.Thread(target=dhcp.netscan_loop, daemon=True).start()
    threading.Thread(target=dhcp.dhcp_watch_loop, daemon=True).start()
    threading.Thread(target=wifi.wifi_loop, daemon=True).start()
    threading.Thread(target=unifi.unifi_loop, daemon=True).start()
    threading.Thread(target=outbox.outbox_loop, daemon=True).start()
    threading.Thread(target=services.groups_loop, daemon=True).start()
    threading.Thread(target=video.video_loop, daemon=True).start()
    if telegram.telegram_ready():
        alerting.emit("system", f"🚀 <b>{core.cfg('app_name')}</b> запущен. Напиши /status для сводки.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


def run_cli():
    """Command line: --version, --update-swap, --set-password, --wifi-sensor, or the monitor."""
    if "--version" in sys.argv:
        print(core.__version__)
        sys.exit(0)
    if "--update-swap" in sys.argv:
        sys.exit(update.update_swap_main(sys.argv[sys.argv.index("--update-swap") + 1]))
    if "--set-password" in sys.argv:
        webauth.set_password_cli()
    elif "--wifi-sensor" in sys.argv:
        _i = sys.argv.index("--wifi-sensor")
        _a = sys.argv[_i + 1:]
        if len(_a) < 2:
            print("usage: monitor.py --wifi-sensor <brain-url> <api-token> [sensor-name] [interval-sec]")
            sys.exit(1)
        wifi.wifi_sensor_main(_a[0], _a[1],
                         _a[2] if len(_a) > 2 else "",
                         int(_a[3]) if len(_a) > 3 else 60)
    else:
        main()
