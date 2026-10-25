# Putting KEVShift on GitHub (beginner steps, Windows)

## A. One-time setup
1. Create a free account at https://github.com.
2. Install Git for Windows: https://git-scm.com/download/win (default options are fine; no admin rights needed
   if you choose the per-user installer).
3. Open Command Prompt and tell Git who you are:
   ```
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```

## B. Create the repository on GitHub
1. On github.com click **+ -> New repository**.
2. Name: `kevshift`. Choose **Private** while it is a student project (you can make it public later).
3. Do **not** tick "Add a README", ".gitignore" or "license" (the project already has files). Click **Create repository**.
   Leave the page open; it shows your repository address, like `https://github.com/YOUR-USER/kevshift.git`.

## C. Push the project
In Command Prompt, go **into the project folder** (the one with `app.py`):
```
cd /d C:\Users\YourName\Downloads\kevshift
git init
git add .
git status
git commit -m "KEVShift: complete project"
git branch -M main
git remote add origin https://github.com/YOUR-USER/kevshift.git
git push -u origin main
```
* `git status` before committing should **not** list `data/` contents, `.venv`, or `__pycache__` (`.gitignore` excludes them).
* The first push opens a browser window to sign in to GitHub. If asked for a password in the terminal, GitHub no longer
  accepts account passwords: use the browser sign-in, or create a *Personal access token* under
  Settings -> Developer settings and paste it as the password.
* If `git push` says `remote origin already exists`, run `git remote set-url origin https://github.com/YOUR-USER/kevshift.git`.

## D. Later changes
```
git add .
git commit -m "Describe what you changed"
git push
```

## E. Test from a clean copy (proves the repository works)
```
cd /d C:\Users\YourName\Desktop
git clone https://github.com/YOUR-USER/kevshift.git kevshift_check
cd kevshift_check
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pytest
python -m streamlit run app.py
```
Expected: `154 passed`, and the dashboard opens at http://localhost:8501.

## F. Optional: automatic tests on every push (GitHub Actions)
Create the file `.github/workflows/tests.yml` with this content, commit and push:
```
name: tests
on: [push, pull_request]
jobs:
  pytest:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -r requirements.txt
      - run: python -m pytest
```
Open the **Actions** tab on GitHub to see a green check when tests pass.

## G. What not to upload
Never commit real scan files, real asset names or passwords. `data/` is git-ignored for that reason; the `sample_data/`
files are synthetic and safe.
