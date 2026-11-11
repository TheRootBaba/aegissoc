from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright


SECTIONS = (
    "overview",
    "sources",
    "alerts",
    "events",
    "cases",
    "connectors",
    "detection-rules",
    "threat-intel",
    "asset-risk",
    "response-playbooks",
    "audit",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture screenshots from a live, authenticated AegisSOC dashboard."
    )
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/assets/screenshots"),
    )
    parser.add_argument(
        "--sections",
        nargs="+",
        choices=SECTIONS,
        default=["overview", "sources", "alerts", "events", "cases", "connectors", "audit"],
    )
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1000)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
        page = browser.new_page(
            viewport={"width": args.width, "height": args.height},
            device_scale_factor=1,
        )
        page.goto(args.base_url.rstrip("/") + "/dashboard", wait_until="domcontentloaded")

        print("\nAegisSOC is open in Chromium.")
        print("Sign in with your local test account and wait for the dashboard data to load.")
        input("When the workspace is ready, press Enter here to capture screenshots... ")

        overlay = page.locator("#auth-overlay")
        if overlay.count() and "hidden" not in (overlay.get_attribute("class") or "").split():
            browser.close()
            raise SystemExit("The dashboard is still showing the sign-in overlay; no screenshots were saved.")

        username = page.locator("#sidebar-username").inner_text().strip()
        if not username or username.lower() == "analyst":
            browser.close()
            raise SystemExit("A signed-in analyst identity was not detected; no screenshots were saved.")

        for section in args.sections:
            link = page.locator(f'a[data-nav="{section}"]')
            if not link.count():
                print(f"Skipping unavailable dashboard section: {section}")
                continue
            link.click()
            page.locator(f'a[data-nav="{section}"].active').wait_for(state="visible", timeout=5000)
            page.wait_for_timeout(900)
            page.screenshot(
                path=str(args.output_dir / f"{section}.png"),
                full_page=True,
                animations="disabled",
            )
            print(f"Captured {section}.png")

        browser.close()

    print(f"\nScreenshots saved to: {args.output_dir.resolve()}")
    print("Review every image for personal data, hostnames, IPs and secrets before committing it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
