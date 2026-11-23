# Time-Locked Encrypted File Vault

A Flask + SQLite web application prototype for the CNS project **Time-Locked Encrypted File Vault with Expiry-Based Access Control and Access Logging**.

## What is implemented

- Account registration, login and logout.
- Upload a file and set a file expiry date/time.
- Encrypt file contents using **AES-256-GCM** before writing them to local storage.
- Generate a fresh AES key for every file.
- Wrap each AES key with an **RSA-OAEP / SHA-256** public key.
- Create unguessable sharing URLs that can be copied, shared through the device share sheet, WhatsApp, email or any messaging app.
- Reopen active links from **Shared Links** and copy them again; link tokens are stored encrypted with the RSA public key.
- Optional password protection for each sharing link. Share the password separately from the URL.
- Independent link expiry, which cannot be later than the encrypted file's expiry.
- Server-side expiry checks every time a recipient opens or downloads a file.
- Revoke a link before its expiry.
- Recipient page to validate access and download/decrypt the file.
- Access logs for encryption, link creation, link view, password checks, downloads, denied access and revocation.
- Admin monitoring dashboard.
- Isolation Forest anomaly detection for repeated failed logins, excessive downloads, denied access bursts, unusual activity volumes, and abnormal file-access patterns.
- Administrator review workflow for marking detections as reviewed or false positives.
- Responsive navy-blue and white interface based on the approved UI storyboard.

## Requirements

- Windows 10/11, macOS or Linux
- Python 3.10 or newer
- Internet connection for the first-time pip install (the UI loads the Inter font from Google Fonts; it falls back to system fonts without internet)

## Run on Windows

1. Extract the ZIP file into a normal folder.
2. Open that folder in VS Code.
3. Open Terminal in VS Code.
4. Run:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

5. Open `.env` and replace `FLASK_SECRET_KEY` with a long random value. The default upload limit is 100 MB; change `MAX_UPLOAD_MB` there if needed. Generate the secret with:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

6. Start the app:

   ```powershell
   $env:FLASK_APP = "app.py"
   flask run
   ```

7. Open **http://127.0.0.1:5000** in your browser.

**Sharing note:** while running locally, generated links use `127.0.0.1` and work only on the same computer. To let friends open links from their own devices over the internet, deploy the app to an HTTPS host first; then generate and share links from that hosted app.

You can also double-click `run_windows.bat` to create the virtual environment, install packages and start the local server. For the first run, edit `.env` after the script creates it, then restart the app so the secret key is loaded.

## First-use workflow

1. Register a new account.
2. Log in and open **Upload & Encrypt**.
3. Select a file and set the file's expiry date and time.
4. The app encrypts the file and opens its details page.
5. Select a link expiry time (it must be at or before the file expiry). Add an optional link password, then click **Generate secure link**.
6. Copy the generated link and send it to another person. The recipient does not need an account. They open the URL, enter the separate password if enabled, and download the decrypted file while access is valid.
7. Use **Shared Links** to copy active links or revoke them. Use **Access Logs** to review events.


## AI anomaly detection (Isolation Forest)

The administrator-only **Anomaly Detection** page analyses File Vault activity logs using an unsupervised Isolation Forest model.

### What it analyses

- Failed login attempts grouped by privacy-preserving network fingerprint.
- Successful file downloads and download frequency.
- Denied or failed file-access events.
- Overall event volume and short five-minute activity bursts.
- Number of distinct files accessed in an analysis window.
- Number of network fingerprints and activity-time patterns.

Activity is aggregated into 15-minute actor windows. The Isolation Forest model uses 13 behavioural features and a fixed random seed so the same log set produces reproducible results. Model fitting begins when at least five activity windows are available. For smaller datasets, transparent behaviour thresholds still flag obvious patterns, and the interface clearly reports that the ML baseline is not yet trained. The score is a relative outlier ranking from 0 to 1, **not** a probability of malicious behaviour.

### How to use it

1. Register your normal account and enable the administrator role using the command below.
2. Use the vault normally: attempt a few incorrect logins, upload files, open shared links, and download files.
3. Log in as an administrator and open **Anomaly Detection** in the sidebar.
4. Select the last 24 hours, 7 days, or 30 days and click **Run analysis**.
5. Review the detected patterns, inspect the evidence, then mark a finding as **Reviewed** or **False Positive**.
6. Delete individual analysis findings or clear the saved analysis history. Clearing anomaly history does not delete the original access logs.

The detector is an alerting aid, not proof of an attack. Administrators should review the evidence and context before taking action.

### Activity identity and privacy

Authenticated activity is grouped by user ID. Unauthenticated activity (such as recipient link views and failed logins) is grouped using an HMAC fingerprint of the connecting IP address; raw IP addresses are not stored. Behind a reverse proxy, configure trusted proxy handling deliberately before production deployment. Do not blindly trust client-supplied `X-Forwarded-For` headers.

## Create an administrator account

Register the account first, then run this command from the project folder with the virtual environment active:

```powershell
flask --app app create-admin --email your-email@example.com
```

Log out and log in again. The **Admin Monitoring** and **Anomaly Detection** links will appear in the administrator sidebar.

## Important security notes

- This is a college-project prototype intended for local development and controlled demonstrations. Do not expose it to the public internet as-is.
- Files are encrypted at rest with AES-256-GCM. The app's RSA private key is kept in `instance/rsa_private_key.pem`; the server needs it to unwrap AES keys after access validation. Back up this private key securely. If it is lost, uploaded files cannot be decrypted. Do not include `instance/` or `storage/` in source control or share them publicly.
- Because the server can decrypt a file after authorization, this design is **server-side encryption**, not end-to-end encryption.
- A share URL is a bearer secret. Anyone who obtains it can try to access the file until it expires or is revoked. Use the optional link password for sensitive files and send that password through a different channel.
- Expiry prevents new server-side downloads after the deadline. It cannot erase a file that someone already downloaded before expiry.
- The default upload limit is 100 MB (`MAX_UPLOAD_MB` in `.env`). The hosting platform or reverse proxy may impose a lower request-size limit and must be configured to allow the same size. The prototype does not include malware scanning, email delivery, rate limiting, multi-factor authentication, or cloud object storage.
- Before deployment, use HTTPS, set a strong `FLASK_SECRET_KEY`, set `COOKIE_SECURE=1`, protect and back up the RSA private key, configure a production WSGI server, add rate limiting and monitoring, and review the full deployment security.

## Project structure

```text
time_locked_file_vault/
├── app.py
├── requirements.txt
├── README.md
├── design_reference.png
├── anomaly_detection_reference.png
├── anomaly_detector.py
├── .env.example
├── run_windows.bat
├── instance/       # SQLite database and RSA key pair are generated here
├── storage/        # Encrypted .vault files are stored here
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── home.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── upload.html
    ├── my_files.html
    ├── file_detail.html
    ├── link_generated.html
    ├── shared_links.html
    ├── access_logs.html
    ├── share_password.html
    ├── recipient_view.html
    ├── share_unavailable.html
    ├── admin.html
    ├── anomaly_detection.html
    └── error.html
└── tests/
    └── test_anomaly_detector.py
```

## UI polish and history controls

- Soft entrance animations for page sections and dashboard cards, gentle hover motion, and animated upload/empty-state accents.
- Responsive rounded cards, clearer spacing and navy/blue styling throughout the app.
- Drag-and-drop file selection on the upload screen.
- A styled confirmation dialog appears before destructive actions.
- **Access Logs:** delete one event with its trash icon, or use **Clear history** to remove the current user's audit history.
- **Shared Links:** copy an active URL, revoke it while keeping its record, or delete the link record with the trash icon. Deleting an active record invalidates its URL immediately. Related audit log entries are retained.
- **Admin Monitoring:** administrators can delete a single security event or clear the full system audit history.

Deleting access-log history is permanent. These controls are included for the project demonstration; a production audit system would normally keep immutable logs and use a separate retention policy.

## Run the anomaly detector tests

After installing the project requirements in the activated virtual environment, run:

```powershell
python -m unittest discover -s tests -v
```

The tests exercise empty history, repeated failed logins, excessive downloads, and the Isolation Forest training path using synthetic test events. They do not insert test events into your live File Vault database.

### Updating an existing File Vault installation

1. Stop the Flask server.
2. Copy the updated source files into your project folder.
3. Keep your existing `.env`, `instance/`, and `storage/` folders. The database migration adds the activity identity and anomaly tables when the app next starts; it does not delete existing users or encrypted files.
4. Activate your existing virtual environment and run `pip install -r requirements.txt` so NumPy and scikit-learn are installed.
5. Start Flask again. Register an account if needed, then promote it with the `create-admin` command above.
