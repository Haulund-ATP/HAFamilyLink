# Example dashboard

A ready-to-use Lovelace dashboard built around the Google Family Link integration: screen time, per-device limits, bedtime and daily limit toggles, time bonuses, app usage and a location map.

![Family Link demo dashboard](dashboard.png)

## Import it

1. **Settings > Dashboards > + Add dashboard > New dashboard from scratch**, give it a name.
2. Open it, **Edit dashboard**, *Take control*, then open the **Raw configuration editor** (top-right menu).
3. Select everything, delete, paste the contents of [`lovelace-dashboard.yaml`](lovelace-dashboard.yaml), then **Save**.

The file contains two views showing the same cards: a classic masonry view ("Parental Control") and a modern `sections` layout view (`type: sections`, `max_columns: 2`). Keep the one you prefer and delete the other, or keep both.

## Replace the placeholder entities

The YAML was exported from a real setup. Find your own entity ids in **Developer Tools > States** (filter on your child's or device's name) and replace:

| Placeholder | Replace with |
|-------------|--------------|
| `sensor.firstname_name_*` (daily_screen_time, installed_apps, blocked_apps, apps_with_time_limits, device_count, battery_level, top_app_1 to top_app_7) | your child's sensors |
| `switch.firstname_name_bedtime`, `switch.firstname_name_daily_limit` | your child's restriction switches |
| `switch.galaxy_tab_firstname`, `sensor.galaxy_tab_firstname_*` (screen_time_remaining, daily_limit, active_bonus), `button.galaxy_tab_firstname_*` (15min, 30min, 60min, reset_bonus) | your tablet's entities |
| `switch.sm_s916b`, `sensor.sm_s916b_*`, `button.sm_s916b_*` (same set) | your phone's entities |
| `device_tracker.firstname_name_family_link_firstname_name` | your child's device tracker (requires GPS tracking enabled in the integration options) |
| `input_boolean.firstname_mode_school` | a toggle helper you create for school mode |
| `automation.antibonus`, `automation.firstname_antideverrouillage`, `automation.firstname_bedtime_enabler`, `automation.firstname_daily_limit_enabler` | your own automations, or remove those toggle rows |

## Cards that need extra work

A few cards reference entities the integration does **not** create; they come from the author's own helpers and template sensors. Build equivalents or delete those cards:

| Entity | Used for |
|--------|----------|
| `sensor.firstname_pending_requests`, `button.firstname_approve_request`, `button.firstname_deny_request` | app approval request cards |
| `sensor.firstname_ecran_par_heure` | hourly screen time charts (ApexCharts) |
| `sensor.firstname_temps_d_ecran_total` | total screen time counter |

## Required custom cards (HACS)

Install these from **HACS > Frontend** before pasting the YAML, otherwise cards render as "Custom element doesn't exist":

| Card | Element |
|------|---------|
| button-card | `custom:button-card` |
| Mushroom | `custom:mushroom-title-card` |
| Bubble Card | `custom:bubble-card` |
| card-mod | `custom:mod-card` / `card_mod:` |
| stack-in-card | `custom:stack-in-card` |
| vertical-stack-in-card | `custom:vertical-stack-in-card` |
| Swipe Card | `custom:swipe-card` |
| ApexCharts Card | `custom:apexcharts-card` |
| template-entity-row | `custom:template-entity-row` |
| Map Card | `custom:map-card` |

> `card-mod` also needs to be registered as a frontend resource, see the
> [card-mod docs](https://github.com/thomasloven/lovelace-card-mod#installation).

## Theme

Both views set `theme: ios-dark-mode-blue-red` (HACS > Frontend, "iOS Themes"). Change or remove that line to use your own theme; the cards work with any dark theme, only the exact colors differ.
