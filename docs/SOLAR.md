<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# Solar and Powerwall

tcmon can read a **Tesla Backup Gateway 2** on your network, the gateway
of a **Powerwall 2 or Powerwall+** system. With it, tcmon shows
solar production, home use, grid import and export and the Powerwall
battery. It also estimates how much of your car's charging came from
solar, the Powerwalls and the grid, and what the solar share saved. It
alerts on grid outages, a low battery, solar that stopped producing, and
problems reaching the Gateway.

It is **local and read only**. tcmon talks only to the Gateway on your
LAN, never to Tesla's servers, and never changes a Gateway setting: no
operation mode, no backup reserve, no grid charging. The only request that
is not a read is the login.

## What you need

- A Powerwall 2 or Powerwall+ with a **Backup Gateway 2**. Tested on
  Gateway firmware 26.34.2.
- The Gateway connected to your home network (Wi-Fi or Ethernet), so the
  machine running tcmon can reach it.
- The Gateway's **customer password** (see below).

Not supported: the **Powerwall 3** and solar-only systems without a
Gateway. Neither has a known local API.

## 1. Find the Gateway's address

Your router's list of connected devices shows the Gateway, often named
`teg` or listed with Tesla as the manufacturer. Reserve that address for it in the router (a DHCP reservation),
so it does not change later.

The Gateway's own web page now only says to use the Tesla app. That is
expected: the API tcmon uses still answers behind it.

## 2. The customer password

This is **not** your Tesla account password. It is the Gateway's own
password. Unless someone changed it, it is the **last 5 characters of the
password printed on the label inside the Gateway's door**. The label also
has the serial number and a QR code. The full password on the label is
longer; only the last 5 characters are the customer password.

The Gateway locks out repeated failed logins. tcmon is built around that:

- **Saving tests the password with exactly one login.** If it is rejected,
  nothing is saved, and the settings page waits 5 minutes before allowing
  another test.
- **While polling**, a rejected password is never retried at once. tcmon
  waits 5 minutes, then 10, 20 and so on up to 6 hours between attempts,
  even across restarts, and raises the *Gateway login failed* alert.
  Saving a new password retries at once.

The password is stored encrypted with the same key as your email password
(`secret.key` in the data directory). Back up that file with the database.

## 3. Add it in tcmon

**Settings → Solar Gateway**:

1. Enter the address and choose **Find Gateway**. tcmon connects without
   logging in and shows the certificate's **SHA-256 fingerprint**.
2. The Gateway uses a self-signed certificate, so tcmon remembers this one
   (it *pins* it) and refuses any other later. Tick **This is my Gateway;
   trust this certificate** only if the address is your Gateway.
3. Enter the customer password and **Save**. tcmon logs in once and shows
   what it found, for example *Connected: firmware 26.34.2, 2 Powerwall(s),
   battery 32 %, solar 3730 W*.

The Gateway is polled every 15 minutes, and every 5 minutes while a car is
plugged in (both adjustable on the same page). A **Solar** page appears in
the menu.

Without the web UI, the same can be done with `tcmon gateway fingerprint`
and `tcmon gateway add` (the password is read from standard input or a
file, never from an argument). Run `tcmon gateway` for details.

## What you get

- **Dashboard:** a live card with solar, home, car charging, grid
  (importing or exporting), Powerwall (charging or supplying), battery %
  and grid status, plus the solar produced today and this week and the
  money it saved.
- **Solar page:**
  - Totals for today, this month, this year and all time: solar produced,
    home use, grid import and export, how much solar was used on site,
    and how self-sufficient the home was.
  - Production per day, week, month or year, with the numbers.
  - The last 24 hours of solar and home power and battery level.
- **Costs page:** Solar, Powerwall and Grid columns for charging, and the
  **solar savings**. These figures are approximate. In each polling
  interval, the car is assumed to get the same mix as the rest of the
  home, after the solar that was exported or stored in the Powerwalls is
  set aside. Powerwall energy is not counted as savings, because the
  batteries may have charged from the grid. Export credits are not
  included. The CSV downloads gain the same columns.
- **Costs page, solar production and savings:** solar produced and the
  money it saved today, this week, this month, this year and since tcmon
  started, and the Gateway meter's lifetime production (tcmon cannot
  price energy from before it started). Under **Settings → Energy cost →
  Solar savings**, choose how savings are counted:
  - **Solar used at home** (the default): solar the home used directly,
    plus Powerwall energy estimated to have come from solar. tcmon tracks
    how much of what is stored in the Powerwalls was charged from solar
    and how much from the grid, and counts each discharge in that
    proportion. Exports earn nothing.
  - **All solar produced (net metering)**: every solar kWh, as if exports
    were credited at the full retail rate.

  Either way, energy is priced at your electricity rate when it was
  produced or used, off-peak prices included.
- **Alerts:**
  - Grid outage, with a notice when the grid is back.
  - Powerwall battery low, below 20 % by default; a warning during an
    outage.
  - No solar in daylight: under 50 W for 2 hours between 10:00 and 15:00.
    Adjust the window for your season.
  - Low solar day: off by default, because cloudy days trigger it too.
  - Powerwall capacity dropped.
  - Gateway unreachable, Gateway login failed, Gateway certificate
    changed.
  - Gateway firmware updates and restarts.
- **Summary emails:** a solar section in the weekly and monthly summaries.

Battery percentages match the Tesla app. The Gateway itself reports a
slightly higher figure that includes a hidden 5 % reserve; tcmon converts
it the same way the app does.

## If the certificate changes

The Gateway's certificate changes after a Gateway replacement or a factory
reset. tcmon then stops polling it, does not send the password, and raises
*Gateway certificate changed*. Check that the address is still your
Gateway. Then, on **Settings → Solar Gateway**, compare the new
fingerprint and accept it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| *No Tesla Backup Gateway answered* | Check the address and that the tcmon host can reach that network. |
| *The Gateway rejected the password* | Use the label's last 5 characters, not the Tesla account password. Wait 5 minutes before the next try. |
| *Gateway login failed* alert, and polling waits hours | The password changed or is wrong. Enter it again: a new password is tried at once. |
| *Gateway certificate changed* alert | See [If the certificate changes](#if-the-certificate-changes). |
| Solar figures on the Costs page show – | The Gateway was unreachable while the car charged; that charging is left out of the split rather than guessed. |
