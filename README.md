# WatchTower

WatchTower is a small, local Windows user activity monitoring prototype for the cybersecurity internship project. This Python version adapts the supplied Java/Spring synopsis to a dependency-free stack that can be run without installing Spring, Maven, or database software.

## Current prototype

- Local dashboard at `http://127.0.0.1:8765`.
- First-run local account setup and a sign-in screen protect the dashboard. The password is stored as a salted PBKDF2 hash; browser sessions expire after 12 hours and end when WatchTower exits. Monitoring continues while WatchTower is running, even when the dashboard is signed out.
- Graphite-and-gold WatchTower logo supplied for the project, used on the sign-in screen and dashboard header (`watchtower_logo.png` and its compact `watchtower_emblem.png` crop).
- Local SQLite storage in `watchtower.db`.
- Windows Security event monitoring for interactive successful sign-ins (4624 logon types 2, 10, and 11), failed sign-ins (4625), and workstation unlocks (4801). Background service and network logons are filtered to avoid confusing duplicates. The app checks that its Windows account can read the Security log and reports access or audit-policy errors as unavailable instead of treating them as an empty log.
- Rule-based failed-sign-in alert (default: 1 failure within 5 minutes), including the account name. A cooldown prevents repeat notifications for the same burst.
- Separate Windows sign-in history panel showing the latest 10 captured entries with status, account name, date, and time; a “View detailed history” button loads all entries from the current WatchTower session. Sign-in history and security alerts reset when WatchTower starts. Same-second successful-logon/unlock duplicates are shown once, preferring the unlock record. Existing events before startup are not replayed. Unlock events depend on Windows auditing them.
- Individual file monitoring with SHA-256 fingerprints and create/modify/delete records. Each activity row has a collapsed “See before and after” arrow for readable UTF-8 text previews. The dashboard can roll back a change when a saved snapshot is available and the file has not changed again.
- Recent activity uses filenames only; **Clear recent activity** removes file activity entries and their Undo actions while retaining baselines for ongoing monitoring.
- Active-window application change logging with an Active/Inactive indicator, a current-session estimated focus-time chart, app badges, and expandable recent window titles. Time estimates are based on the time between switches and cap long gaps to reduce counting idle time or sleep. The app lock password is configured in Settings; the lock and clock controls are beside each usage row. Daily time limits of 15, 30, or 45 minutes can automatically lock an app, and WatchTower closes a locked app while it is running.
- Browse opens a file picker. WatchTower monitors only the selected file, not its containing folder.
- A live Collector status panel on the main dashboard. The Settings dialog, opened from the gear icon, contains persistent email alert settings.
- One-click PDF activity report download, containing up to 150 recent file changes, the current session's sign-in history and alerts with attempt timestamps, up to 200 app switches (app names only), and monitored locations. PDF generation uses Python's standard library and needs no extra package.
- Optional SMTP email for security alerts.
- A dashboard action to lock the current Windows session.

The app binds to loopback only and runs in the foreground. It does not install a service, hide itself, start automatically, or send activity to a remote server. File snapshots are kept in the local `rollback_data` folder. Use it only on a device you own or are authorized to monitor.

Windows sign-in monitoring may require starting WatchTower from an elevated PowerShell window because Windows restricts access to the Security log. The file monitor and dashboard do not otherwise require elevation.

## Run on Windows

1. Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/).
2. Open PowerShell in this folder.
3. Start the app:

   ```powershell
   py .\watchtower.py
   ```

4. Open `http://127.0.0.1:8765` in your browser.
5. Select a test file from the dashboard and wait for the baseline. Edit or delete that file to see the events.
6. Keep the PowerShell window open while monitoring. Press `Ctrl+C` to stop.

No third-party Python packages are required. Windows Security log access depends on local policy and permissions. If the dashboard says the log is unavailable, run the PowerShell window as an administrator or enable the relevant Windows audit policy. A successful first connection establishes the current event-log position; activity from before WatchTower started is not replayed.

## Reset a forgotten dashboard password

Stop WatchTower with `Ctrl+C` in its PowerShell window. In PowerShell in this folder, run:

```powershell
python .\watchtower.py --reset-login
python .\watchtower.py
```

Open the dashboard and create a new username and password (at least 10 characters). This clears only the dashboard login credentials; monitoring history, watched locations, and email settings remain in place.

## Optional email alerts

Open **Settings** from the dashboard gear icon, enter the sender, recipient, and mail account details, then select **Save email settings**. The SMTP server defaults to `smtp.gmail.com` on port `587`. Use a Google app password rather than the account password, then select **Send test email** to confirm delivery. The settings persist in the local database, and the mail password is protected with Windows DPAPI for the current Windows account. A blank password field keeps the saved password. Collector status is also available in Settings.

Email is optional; events and alerts still appear on the dashboard when mail is not configured. The main dashboard's Collector status panel shows whether email is configured, sending, sent, or failed. WatchTower emails when the failed-sign-in threshold is reached, rather than emailing for every successful sign-in or every failed attempt within the alert cooldown. Existing `WATCHTOWER_SMTP_*` and `WATCHTOWER_ALERT_TO` environment variables remain supported as a fallback.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WATCHTOWER_PORT` | `8765` | Local web dashboard port |
| `WATCHTOWER_FAILURE_THRESHOLD` | `1` | Failed sign-ins required for an alert |
| `WATCHTOWER_FAILURE_WINDOW_MINUTES` | `5` | Time window for the failure rule |

The SMTP variables above configure optional email delivery. The database and snapshots are local and should be treated as sensitive because they can contain account names, window titles, file paths, and previous file contents. Previous versions are saved for rollback when files are up to 25 MB; text previews are shown for UTF-8 files up to 256 KB. A newly created file can be removed only while its contents still match the recorded event. Stop the app before moving or deleting `watchtower.db` or `rollback_data`.

## Limitations and next steps

- Windows Security event collection depends on audit configuration and account permissions; event fields and coverage can vary by Windows setup.
- Active-window collection records the foreground app and window title only when the active window changes. It does not capture keystrokes, screenshots, browser history, or content typed into apps.
- File monitoring checks each selected file every five seconds. Protected or unavailable files may not be readable.
- The failed-sign-in threshold alert is a signal for review, not proof of an attack, and does not block Windows accounts.
- The dashboard is intended for local demonstration, not multi-user or network deployment. It has no user-account system, TLS, or production hardening.
- Data is stored locally in SQLite rather than MySQL. A later version can replace the storage layer and add account authentication, alert acknowledgement, monitored-path removal, reports, and a packaged installer.

## Suggested demo for October 20

1. Start WatchTower and show the dashboard's Collector status panel.
2. Add a test file, wait for baseline, then modify or delete it. Review the text diff and use the Undo button on a test change.
3. Demonstrate application change records by switching between a few windows.
4. Switch between a few applications while WatchTower is running. The Application activity chart estimates time spent in each app during the current session.
5. If Windows auditing is available, show sign-in events and explain the threshold rule. Do not deliberately lock yourself out by generating repeated bad passwords.
6. Optionally configure SMTP and show an alert email using a test threshold in a separate environment variable configuration.
7. Explain permissions, local-only behavior, false positives, and the documented limitations.

