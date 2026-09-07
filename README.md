# Roznamcha — Deployment Guide (Free)

Ye guide aap ko step-by-step batati hai ke is app ko **bilkul free** internet pe kaise dalein, taake
aap ke sab staff apne PC/laptop se ek link kholain aur login karain — data ek hi jagah, hamesha sync.

Total waqt: tqreeban 20-30 minute, ek dafa. Do free services use hongi:

- **Supabase** — database (aap ka asal data yahan mehfooz rehta hai, hamesha)
- **Render** — jahan app khud chalti hai (link jo aap staff ko dengay)

Dono bilkul free hain, koi credit card zaroori nahi.

---

## Step 1 — GitHub account aur code upload

1. https://github.com pe jaa kar free account banayein (agar pehlay se nahi hai).
2. "New repository" par click karein, naam dein `roznamcha` (private ya public, dono chalay ga), Create karein.
3. Us repo ke page par "uploading an existing file" link par click karein.
4. Is folder ke **andar ki tamam files aur folders** (package.json, server.js, store.js, public/, .gitignore, README.md) drag-and-drop kar dein — ek-ek karke command line se nahi, seedha browser mein.
5. Neeche "Commit changes" par click kar dein.

Ab aap ka code GitHub par hai — is se Render seedha connect ho ga.

---

## Step 2 — Supabase par free database banayein

1. https://supabase.com pe jaa kar free account banayein.
2. "New project" — koi bhi naam dein (jaise `roznamcha-db`), ek strong database password set karein **aur ise kahin likh lein**, region "closest to you" ya default rehnay dein.
3. Project create hote hi 1-2 minute lagega.
4. Project khulnay ke baad: **Project Settings (gear icon) → Database → Connection string** par jaein.
5. "URI" tab select karein, wahan se poora connection string copy kar lein — kuch aisa dikhega:
   `postgresql://postgres.xxxx:[YOUR-PASSWORD]@aws-xxxx.pooler.supabase.com:6543/postgres`
6. `[YOUR-PASSWORD]` ki jagah apna wahi password likh dein jo step 2 mein set kiya tha.
7. Yeh poora string safe jagah copy kar ke rakh lein — agle step mein chahiye ho ga.

**Zaroori:** Supabase free database sirf tab "pause" hoti hai jab **poore 7 din tak koi bhi request na aaye**. Chunke aap ka lab roz-marra istemal karay ga, yeh practically kabhi nahi hoga. Agar kabhi lambi chutti (Eid, etc.) ke baad "pause" ho bhi jaye, Supabase dashboard mein ek click se resume ho jati hai — data hamesha mehfooz rehta hai, sirf temporarily band hoti hai.

---

## Step 3 — Render par app deploy karein

1. https://render.com pe jaa kar "Get Started" — GitHub account se sign in karein (sabse aasan tareeqa).
2. Dashboard mein **New → Web Service** par click karein.
3. Apna `roznamcha` repo select karein aur "Connect" karein.
4. Settings yeh set karein:
   - **Name:** `roznamcha` (ya kuch bhi)
   - **Region:** koi bhi qareeb wala
   - **Branch:** `main`
   - **Build Command:** `npm install`
   - **Start Command:** `node server.js`
   - **Instance Type:** **Free**
5. Neeche "Environment Variables" section mein "Add Environment Variable" par click kar ke yeh add karein:
   - Key: `DATABASE_URL` — Value: wahi connection string jo Supabase se copy kiya tha (Step 2.7)
6. "Create Web Service" par click karein. Render khud build kar ke deploy kar dega — 2-5 minute lagengay.
7. Deploy poora hote hi Render aap ko ek link de ga, jaisay:
   `https://roznamcha.onrender.com`

**Yehi link aap apne sab staff ko share karein.** Wo ise apne PC/laptop/phone ke browser mein kholain, bookmark kar lein — bas.

---

## Step 4 — Pehli baar login

- Username: `admin`
- Password: `admin123`

**Login hote hi sab se pehle Settings mein jaa kar "My Account" se ye password badal dein.**

Us ke baad Settings → Staff mein jaa kar apne 6 staff members ke real accounts bana dein
(naam, username, password, role = Staff). Har banda apne hi username/password se login karay ga —
sirf apna data dekhay ga aur dalay ga. Aap (admin) sab kuch dekh saktay hain aur Settings control kartay hain.

---

## Free tier ka practical matlab

- **Render free service** thori der inactive rehnay ke baad "so" jati hai. Jab koi is link ko dobara kholay,
  pehli request mein 20-30 second lag saktay hain (server "jaagta" hai), phir normal speed. Roz-marra
  office use ke liye yeh koi masla nahi.
- **Data kabhi delete nahi hota** — chahay Render service so jaye, restart ho, ya app update ho — data
  hamesha Supabase database mein mehfooz rehta hai, alag se.
- Dono services (Supabase + Render) **hamesha free** rehti hain is scale (6 staff, roz ki entries) ke liye —
  aap ko future mein paisay dene ki zaroorat nahi parni chahiye, jab tak aap bohot bara scale na kar lein.

---

## Aage koi tabdeeli chahiye ho

Jab bhi mujhe (Claude) is app mein koi naya feature ya tabdeeli karni ho, main aap ko updated files de dunga —
aap sirf GitHub repo mein wohi files dobara upload kar dein ("Commit changes"), Render khud-ba-khud
naya version deploy kar dega. Data hamesha wahi rahay ga (Supabase mein hai, code se alag).


## Admin recovery / protection

The app now protects the main `admin` account so it cannot accidentally be changed to Staff or removed. On server startup/redeploy, if the existing `admin` account is found with the wrong role, its role is automatically restored to `admin`. Existing entries, handovers, categories, employees, vendors, passwords, and other data are not reset.

The server also refreshes the logged-in user's role from the database on each authenticated request, so restoring the admin role takes effect even if an older login token still contains the Staff role. After redeployment, refresh the browser (or log out and log in again) to see the Admin interface.

The system also prevents the last remaining Admin account from being demoted or deleted.
