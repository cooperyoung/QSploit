import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="QSploit — local capture inspector")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="Explicit known-test-factor demonstration mode")
    mode.add_argument("--backend", choices=["aer", "ionq_simulator", "ionq_qpu"])
    parser.add_argument("--demo-delay-seconds", type=float, default=float(os.getenv("QSPLOIT_DEMO_DELAY_SECONDS", "3")))
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--target", default=os.getenv("QSPLOIT_IONQ_TARGET"))
    parser.add_argument("--shots", type=int, default=256)
    parser.add_argument("--max-attempts", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    from .app import Settings, create_app
    import uvicorn
    try:
        settings = Settings(backend="fixture" if args.demo else args.backend or "disabled", demo_delay_seconds=args.demo_delay_seconds, target=args.target, port=args.port, shots=args.shots, max_attempts=args.max_attempts, timeout_seconds=args.timeout_seconds)
    except ValueError as exc:
        parser.error(str(exc))
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, workers=1, access_log=False)


if __name__ == "__main__":
    main()
