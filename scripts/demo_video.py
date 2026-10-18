"""Automated demo video — Playwright drives the SEVER console through the
hero arc and records it.

    python scripts/demo_video.py --console http://127.0.0.1:8000 --out out/demo

Produces a webm screencast of: breach -> attack paths light up -> live ACE grant ->
proposal -> HUMAN GATE (APPROVE CUT arms, CONFIRM CUT executes) -> collapse ->
receipts. Intended as the
video storyboard / backup take; the primary demo video is recorded with
hardware encoding on the build host.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from time import sleep


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--console", default="http://127.0.0.1:8000")
    parser.add_argument("--out", default="out/demo")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        # audit9/M42: playwright is imported by this README §8-documented
        # command but declared nowhere in pyproject.toml (another agent's
        # file — a [video]/dev extra is tracked for security-infra). Fail
        # with the actionable install instead of a raw ModuleNotFoundError.
        print(
            "playwright is not installed — the demo backup take needs it:\n"
            "  pip install playwright\n"
            "  playwright install chromium\n"
            "(see README §8; pyproject extra tracked as audit9/M42)",
            file=sys.stderr,
        )
        return 2

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(out_dir),
            record_video_size={"width": 1440, "height": 900},
        )
        page = ctx.new_page()
        page.goto(args.console.rstrip("/") + "/?static=1", wait_until="networkidle")
        sleep(2)

        # 1) the estate, pre-breach
        page.screenshot(path=str(out_dir / "01_estate.png"))
        sleep(1)

        # 2) breach finding -> reachability 1, paths appear
        page.click("#btn-breach")  # "Simulate breach finding"
        page.wait_for_selector("#paths .hop", timeout=30000)
        sleep(1)
        page.screenshot(path=str(out_dir / "02_breach.png"))

        # 3) the live ACE grant (graph mutation on camera)
        page.click("#btn-grant")  # "Grant new ACE (live mutation)"
        page.wait_for_selector("button.approve", timeout=30000)
        sleep(1)
        page.screenshot(path=str(out_dir / "03_live_grant.png"))

        # 4) the proposal + 2-STEP HUMAN GATE (APPROVE CUT arms, CONFIRM CUT fires)
        page.screenshot(path=str(out_dir / "04_proposal.png"))
        approve = page.query_selector("button.approve")
        rounds = 0
        while approve is not None and rounds < 4:
            approve.click()
            page.wait_for_selector(".btn.confirm", timeout=30000).click()
            page.wait_for_function(
                "document.querySelector('#banner') && document.querySelector('#banner').textContent.includes('verdict')",
                timeout=30000)
            sleep(1.2)
            rounds += 1
            page.screenshot(path=str(out_dir / f"0{4 + rounds}_cut{rounds}.png"))
            approve = page.query_selector("button.approve")

        # 5) final state + receipts
        sleep(1.5)
        page.screenshot(path=str(out_dir / "09_final.png"))

        # close to flush the video
        video = page.video
        path = video.path()
        ctx.close()
        browser.close()

    final = out_dir / "sever_demo.webm"
    if path and Path(path).exists():
        final.write_bytes(Path(path).read_bytes())
        print(f"[video] recorded: {final} ({final.stat().st_size/1024/1024:.1f} MB)")
    print(f"[video] screenshots in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
