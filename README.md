# Lab-Brain

A simple multi-location daily cash-management web app for diagnostic labs.

## Locations included
- NMDC – Main Branch
- NMDC – Ayesha Manzil
- NMDC – AL-Khair
- NMDC – Orangi Town
- Prime Lab

## Business rules
- Staff accounts are assigned to one location.
- Admin/Owner accounts can review all locations.
- Categories are location-specific.
- Income categories are added to Total Revenue.
- Online amount is entered once per staff/day and is already included in Total Revenue.
- Expected Cash = Total Revenue - Online - Expenses.
- Cash Short and Excess Cash are separate handover fields. They cannot both be entered at the same time.
- Actual cash is calculated as Expected Cash - Cash Short + Excess Cash.
- Staff can correct their own entries/online amount on the current date, even after closing the day.
- Staff cannot correct previous dates; previous-date corrections require Admin.
- Cash Short/Excess and remarks are saved with the handover and appear in management reports.
- Existing database records are preserved during normal app updates/migrations.

## Storage
Records are stored in Supabase/Postgres through the `app_state` table, so they survive Render restarts and redeploys.

## Default login on a brand-new database
Username: `admin`
Password: `admin123`

Change the password immediately after first login.

## Deploy
Set `DATABASE_URL` in Render (or another Node hosting provider), then deploy this project. The app listens on the hosting provider's `PORT`.


### Current reporting model
- Staff enter one daily Patient Count total (not patient-wise records).
- Reports include Revenue, Cash Counter Expenses, and Patient Count cards.
- Current-month cards compare month-to-date with the previous month’s same number of days.
- Trend views use only fully completed months: Last 3 or Last 6 Months; the current incomplete month is excluded.
- Admin Today view supports Branch/Location plus a user dropdown filtered to users of the selected branch.
