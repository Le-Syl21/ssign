#!/usr/bin/env python3
"""Generate the GitHub Pages site (English at the root, French under fr/).

Run from anywhere: python3 docs/build_site.py
Pages are plain HTML so search engines index them without JavaScript.
Every statement on the site must be backed by the repository (README,
docs/simplysign-protocol.md, src/, ssign-core/, ssign-pkcs11/, the CI workflow,
the release assets): update this file when the tool changes.
The existing docs/simplysign-protocol.md is left untouched; the site links to it
on GitHub.
"""
import html
import json
import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent
ROOT = DOCS.parent
SITE = "https://le-syl21.github.io/ssign/"
# Google Search Console ownership check (the token belongs to the owner's Google account).
GOOGLE_VERIFICATION = "TqbXre6qrm9jaoj6tFwRRiI2vuQilAZLm6kUJA-etmo"
REPO = "https://github.com/Le-Syl21/ssign"
RELEASES = REPO + "/releases/latest"
DL = REPO + "/releases/latest/download/"
BLOB = REPO + "/blob/main/"
PROTOCOL = BLOB + "docs/simplysign-protocol.md"
CI_FILE = BLOB + ".github/workflows/ci.yml"
TEST_SCRIPT = BLOB + "ssign-pkcs11/tests/sign-all-formats.sh"
INTERMEDIATE = BLOB + "ssign-core/src/certs/ccsca2021.der"
DISCORD = "https://discord.gg/T37DYHmt2j"
CRATE = "https://crates.io/crates/ssign"
OSSLSIGNCODE = "https://github.com/mtrojnar/osslsigncode"
CERTUM_CONTAINER = "https://github.com/hpvb/certum-container"

PAGES = ["index", "download", "getting-started", "github-actions", "pkcs11", "security", "faq"]

# Release asset names come from the CI matrix (`ssign-<label>.<ext>` and
# `ssign-pkcs11-<label>.<ext>`) and carry no version, so
# `releases/latest/download/<asset>` stays valid from one release to the next.
ASSETS = [
    ("linux-x86_64", "tar.gz", "ssign", "libssign_pkcs11.so",
     {"en": ("Linux", "Intel or AMD 64-bit (x86_64)"), "fr": ("Linux", "Intel ou AMD 64 bits (x86_64)")}),
    ("linux-aarch64", "tar.gz", "ssign", "libssign_pkcs11.so",
     {"en": ("Linux", "ARM 64-bit (aarch64)"), "fr": ("Linux", "ARM 64 bits (aarch64)")}),
    ("macos-aarch64", "tar.gz", "ssign", "libssign_pkcs11.dylib",
     {"en": ("macOS", "Apple silicon (M-series chip)"), "fr": ("macOS", "Apple silicon (puce série M)")}),
    ("macos-x86_64", "tar.gz", "ssign", "libssign_pkcs11.dylib",
     {"en": ("macOS", "Intel Mac"), "fr": ("macOS", "Mac à processeur Intel")}),
    ("windows-x86_64", "zip", "ssign.exe", "ssign_pkcs11.dll",
     {"en": ("Windows", "64-bit (x86_64)"), "fr": ("Windows", "64 bits (x86_64)")}),
]

UI = {
    "en": {
        "nav": {"index": "Home", "download": "Download", "getting-started": "Get started",
                "github-actions": "GitHub Actions", "pkcs11": "PKCS#11", "security": "Security", "faq": "FAQ"},
        "other": ("fr", "Version française", "FR"),
        "footer_src": "Source code and issues on GitHub", "footer_chat": "Discord",
        "footer_note": "ssign is free software under the MIT licence. It is an independent client, not affiliated "
                       "with or endorsed by Certum / Asseco; “Certum” and “SimplySign” are their trademarks.",
        "system": "System", "file": "Download", "inside": "Contains",
    },
    "fr": {
        "nav": {"index": "Accueil", "download": "Télécharger", "getting-started": "Prise en main",
                "github-actions": "GitHub Actions", "pkcs11": "PKCS#11", "security": "Sécurité", "faq": "FAQ"},
        "other": ("en", "English version", "GB"),
        "footer_src": "Code source et tickets sur GitHub", "footer_chat": "Discord",
        "footer_note": "ssign est un logiciel libre sous licence MIT. C'est un client indépendant, sans lien avec "
                       "Certum / Asseco ni approuvé par eux ; « Certum » et « SimplySign » sont leurs marques.",
        "system": "Système", "file": "Téléchargement", "inside": "Contient",
    },
}


def version():
    """Current version, read from Cargo.toml (used in structured data only)."""
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def href(page, lang, from_lang):
    """Relative link from a page in `from_lang` to `page` in `lang`."""
    if lang == from_lang:
        base = ""
    else:
        base = "../" if from_lang == "fr" else "fr/"
    return (base + ("" if page == "index" else page + ".html")) or "./"


def url(page, lang):
    return SITE + ("fr/" if lang == "fr" else "") + ("" if page == "index" else page + ".html")


def pre(text):
    """A code block; the text is escaped here so snippets stay verbatim."""
    return f"<pre><code>{html.escape(text.strip(chr(10)))}</code></pre>"


def downloads(lang, module):
    u = UI[lang]
    rows = []
    for label, ext, cli_file, module_file, names in ASSETS:
        name = f"ssign-pkcs11-{label}.{ext}" if module else f"ssign-{label}.{ext}"
        inside = module_file if module else cli_file
        system, detail = names[lang]
        rows.append(f'<tr><td><strong>{system}</strong><br><span class="muted">{detail}</span></td>'
                    f'<td><a class="btn" href="{DL}{name}">{name}</a></td><td><code>{inside}</code></td></tr>')
    return (f'<div class="table"><table class="dl"><thead><tr><th>{u["system"]}</th><th>{u["file"]}</th>'
            f'<th>{u["inside"]}</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def flow(lang):
    """The six signing steps, mirrored from the README diagram."""
    if lang == "en":
        cloud, local = "Certum cloud", "Your machine"
        steps = [(cloud, "Log in", "OAuth login with your e-mail and a 6-digit one-time code → bearer token"),
                 (cloud, "Fetch the card", "card serial and signing certificate"),
                 (local, "Hash", "Authenticode SHA-256 of each file"),
                 (cloud, "Request the signature", "the digest and the certificate → asynchronous task"),
                 (cloud, "Poll", "→ RSA-4096 signature"),
                 (local, "Assemble and embed", "PKCS#7 + certificate chain + RFC 3161 timestamp, written into the file")]
    else:
        cloud, local = "Cloud Certum", "Votre machine"
        steps = [(cloud, "Connexion", "connexion OAuth avec votre e-mail et un code à usage unique à 6 chiffres → jeton d'accès"),
                 (cloud, "Récupération de la carte", "numéro de carte et certificat de signature"),
                 (local, "Hachage", "empreinte Authenticode SHA-256 de chaque fichier"),
                 (cloud, "Demande de signature", "l'empreinte et le certificat → tâche asynchrone"),
                 (cloud, "Attente du résultat", "→ signature RSA-4096"),
                 (local, "Assemblage", "PKCS#7 + chaîne de certificats + horodatage RFC 3161, écrits dans le fichier")]
    items = "".join(f'<li class="{"cloud" if w == cloud else "local"}"><span class="where">{w}</span>'
                    f'<strong>{t}</strong><span>{d}</span></li>' for w, t, d in steps)
    return f'<ol class="flow">{items}</ol>'


# ---------------------------------------------------------------- snippets
# Copied from README.md, src/main.rs, ssign-pkcs11/tests/sign-all-formats.sh
# and .github/workflows/ci.yml.

SIGN_EN = """
# Manual, local — paste the current code from your app:
ssign -e you@example.com -T 123456 app.exe

# Automation — seed once, then hands-off:
export CERTUM_EMAIL=you@example.com
export CERTUM_OTP=YOUR_BASE32_TOTP_SEED       # or the full otpauth:// URI
ssign app.exe installer.dll driver.sys
"""

SIGN_FR = """
# Manuel, en local — collez le code courant de votre appli :
ssign -e vous@example.com -T 123456 app.exe

# Automatisation — la graine une fois, puis sans intervention :
export CERTUM_EMAIL=vous@example.com
export CERTUM_OTP=VOTRE_GRAINE_TOTP_BASE32       # ou l'URI otpauth:// complète
ssign app.exe installeur.dll pilote.sys
"""

WORKFLOW_EN = """
name: Sign

on:
  workflow_dispatch:        # manual only — each run performs a real cloud signature

jobs:
  sign:
    runs-on: ubuntu-latest
    environment: signing    # ← protected environment; see next section
    steps:
      - uses: actions/checkout@v4
      - run: cargo install ssign
      - run: ssign dist/*.exe
        env:
          CERTUM_EMAIL: ${{ secrets.CERTUM_EMAIL }}
          CERTUM_OTP:   ${{ secrets.CERTUM_OTP }}
      - uses: actions/upload-artifact@v4
        with: { name: signed, path: dist/ }
"""

WORKFLOW_FR = """
name: Sign

on:
  workflow_dispatch:        # manuel uniquement — chaque exécution signe réellement

jobs:
  sign:
    runs-on: ubuntu-latest
    environment: signing    # ← environnement protégé ; voir la section suivante
    steps:
      - uses: actions/checkout@v4
      - run: cargo install ssign
      - run: ssign dist/*.exe
        env:
          CERTUM_EMAIL: ${{ secrets.CERTUM_EMAIL }}
          CERTUM_OTP:   ${{ secrets.CERTUM_OTP }}
      - uses: actions/upload-artifact@v4
        with: { name: signed, path: dist/ }
"""

SELF_SIGN = """
  sign-windows:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    environment: signing
    steps:
      # …download the Linux ssign and the Windows artifacts built earlier in the run…
      - name: Sign the Windows binary + module with ssign (via Certum)
        env:
          CERTUM_EMAIL: ${{ secrets.CERTUM_EMAIL }}
          CERTUM_OTP: ${{ secrets.CERTUM_OTP }}
        run: |
          unzip -o dl/ssign-windows-x86_64.zip -d dl
          unzip -o dl/ssign-pkcs11-windows-x86_64.zip -d dl
          # One Certum login signs both the CLI and the module.
          ssign --verbose \\
            -n "ssign" -u "https://github.com/${{ github.repository }}" \\
            dl/ssign.exe dl/ssign_pkcs11.dll

  release:
    needs: [build, sign-windows, sign-apple]
"""

OSSL_EN = """
cargo build -p ssign-pkcs11 --release   # → target/release/libssign_pkcs11.so

export CERTUM_EMAIL=you@example.com CERTUM_OTP=BASE32SEED
osslsigncode sign \\
  -pkcs11module ./target/release/libssign_pkcs11.so \\
  -pkcs11cert 'pkcs11:type=cert' -key 'pkcs11:type=private' \\
  -ac certum-code-signing-2021-ca.pem \\
  -h sha256 -t http://time.certum.pl/ \\
  -in installer.msi -out installer-signed.msi
"""

OSSL_FR = """
cargo build -p ssign-pkcs11 --release   # → target/release/libssign_pkcs11.so

export CERTUM_EMAIL=vous@example.com CERTUM_OTP=GRAINE_BASE32
osslsigncode sign \\
  -pkcs11module ./target/release/libssign_pkcs11.so \\
  -pkcs11cert 'pkcs11:type=cert' -key 'pkcs11:type=private' \\
  -ac certum-code-signing-2021-ca.pem \\
  -h sha256 -t http://time.certum.pl/ \\
  -in installeur.msi -out installeur-signe.msi
"""

INTER_PEM = "openssl x509 -inform DER -in ccsca2021.der -out certum-code-signing-2021-ca.pem"

LABEL_URIS = """
pkcs11:object=Certum%20SimplySign%20%28ssign%29;type=cert
pkcs11:object=Certum%20SimplySign%20%28ssign%29;type=private
"""

APT = "apt-get install osslsigncode libengine-pkcs11-openssl"

SMOKE = """
CERTUM_EMAIL=you@example.com CERTUM_OTP=SEED \\
  ssign-pkcs11/tests/sign-all-formats.sh
"""

INSTALL_UNIX = """
tar xzf ssign-linux-x86_64.tar.gz
sudo install -m755 ssign /usr/local/bin/ssign
ssign --help
"""


def options_table(lang):
    """The command-line options, from the clap definition in src/main.rs."""
    if lang == "en":
        head = ("Option", "Environment variable", "What it does")
        rows = [
            ("FILES", "", "Files to sign. Signed in place unless <code>-o</code> is given."),
            ("-e, --email &lt;EMAIL&gt;", "CERTUM_EMAIL", "Certum account e-mail. Required."),
            ("-O, --otp &lt;SEED&gt;", "CERTUM_OTP", "TOTP seed (base32, or a full <code>otpauth://</code> URI): ssign "
             "derives the 6-digit code itself. For CI and automation."),
            ("-T, --token &lt;CODE&gt;", "CERTUM_TOKEN", "A current 6-digit code from your authenticator app. For a "
             "one-off manual signing."),
            ("-o, --output-dir &lt;DIR&gt;", "", "Write signed files to this folder (created if needed) instead of "
             "overwriting them."),
            ("--timestamp-url &lt;URL&gt;", "", "RFC 3161 timestamp authority. Default: <code>http://time.certum.pl/</code>."),
            ("-n, --name &lt;TEXT&gt;", "", "Signature description embedded in the file."),
            ("-u, --url &lt;URL&gt;", "", "Signature info URL embedded in the file."),
            ("--backup", "", "When signing in place, keep the original next to it as <code>&lt;file&gt;.orig</code>."),
            ("-v, --verbose", "", "Print each step (login or cached session, card, each file)."),
            ("-h, --help / -V, --version", "", "Show the help or the version."),
        ]
    else:
        head = ("Option", "Variable d'environnement", "Effet")
        rows = [
            ("FILES", "", "Les fichiers à signer. Signés sur place, sauf avec <code>-o</code>."),
            ("-e, --email &lt;EMAIL&gt;", "CERTUM_EMAIL", "E-mail du compte Certum. Obligatoire."),
            ("-O, --otp &lt;SEED&gt;", "CERTUM_OTP", "Graine TOTP (en base32, ou une URI <code>otpauth://</code> "
             "complète) : ssign calcule lui-même le code à 6 chiffres. Pour la CI et l'automatisation."),
            ("-T, --token &lt;CODE&gt;", "CERTUM_TOKEN", "Un code à 6 chiffres en cours de validité, lu dans votre appli "
             "d'authentification. Pour une signature manuelle ponctuelle."),
            ("-o, --output-dir &lt;DIR&gt;", "", "Écrit les fichiers signés dans ce dossier (créé au besoin) au lieu "
             "d'écraser les originaux."),
            ("--timestamp-url &lt;URL&gt;", "", "Serveur d'horodatage RFC 3161. Par défaut : "
             "<code>http://time.certum.pl/</code>."),
            ("-n, --name &lt;TEXT&gt;", "", "Description de la signature, intégrée au fichier."),
            ("-u, --url &lt;URL&gt;", "", "URL d'information de la signature, intégrée au fichier."),
            ("--backup", "", "En signature sur place, garde l'original à côté sous le nom <code>&lt;fichier&gt;.orig</code>."),
            ("-v, --verbose", "", "Affiche chaque étape (connexion ou session en cache, carte, chaque fichier)."),
            ("-h, --help / -V, --version", "", "Affiche l'aide ou la version."),
        ]
    # data-label lets the narrow-screen CSS stack each row with its column names.
    body = "".join(f'<tr><td data-label="{head[0]}"><code>{o}</code></td>'
                   f'<td data-label="{head[1]}">{f"<code>{e}</code>" if e else "–"}</td>'
                   f'<td data-label="{head[2]}">{d}</td></tr>'
                   for o, e, d in rows)
    return (f'<div class="table"><table class="opts"><thead><tr><th>{head[0]}</th><th>{head[1]}</th><th>{head[2]}</th>'
            f"</tr></thead><tbody>{body}</tbody></table></div>")


# ---------------------------------------------------------------- FAQ data
# (question, answer HTML) pairs; also emitted as FAQPage structured data.

def faq_items(lang):
    p = lambda name: href(name, lang, lang)  # noqa: E731
    if lang == "en":
        return [
            ("Can I use a Certum SimplySign certificate on Linux without SimplySign Desktop?",
             f'<p>Yes. ssign talks to the SimplySign cloud over HTTPS by itself: it logs in, fetches your certificate '
             f'and asks the cloud to sign, with no SimplySign Desktop, no GUI, no container and no PKCS#11 stack. It '
             f'runs on Linux, macOS and Windows. See <a href="{p("getting-started")}">Get started</a>.</p>'),
            ("Do I need Windows to sign a Windows .exe?",
             f'<p>No. Authenticode signing is data: ssign hashes the file, gets the RSA signature from the cloud and '
             f'builds the PKCS#7 signature itself, with no Windows API. ssign\'s own Windows release is signed that way, '
             f'from a Linux runner.</p>'),
            ("Can I sign in GitHub Actions or another CI?",
             f'<p>Yes. Give ssign <code>CERTUM_EMAIL</code> and the TOTP seed in <code>CERTUM_OTP</code>, and it '
             f'computes the one-time code on each run. Keep the seed in a protected environment that needs your '
             f'approval: see <a href="{p("github-actions")}">GitHub Actions</a>.</p>'),
            ("Which file types can it sign?",
             f'<p>The <code>ssign</code> command signs PE files: <code>.exe</code>, <code>.dll</code>, <code>.sys</code>, '
             f'<code>.ocx</code>, <code>.cpl</code>. For MSI, CAB, catalogs, APPX and PowerShell scripts, use the '
             f'<a href="{p("pkcs11")}">PKCS#11 module</a> with osslsigncode. Native MSI signing in the command itself '
             f'is still in progress.</p>'),
            ("What is the TOTP seed, and do I have to store it?",
             f'<p>It is the base32 secret behind the authenticator you set up from the SimplySign QR code. It is '
             f'long-lived: with it and your e-mail, anyone can sign as you until you re-issue the QR code. You only need '
             f'it for automation (<code>--otp</code>). On your own machine, pass the current code with '
             f'<code>--token</code> instead, and the seed never leaves your authenticator app. See '
             f'<a href="{p("security")}">Security</a>.</p>'),
            ("Login fails with “no authorization code after login — wrong e-mail or OTP?”",
             f'<p>Certum did not accept the e-mail and code. Check the e-mail, and that the code is current: a code is '
             f'valid for about 30 seconds and Certum accepts it only once. With <code>--otp</code>, ssign computes the '
             f'code from the system clock, so that clock has to be right.</p>'),
            ("I sign several files, or run ssign several times. Do I need a new code each time?",
             f'<p>No. One login signs every file given on the command line. The session is also cached for 20 minutes, '
             f'so the next runs, and the PKCS#11 module, reuse it without a new code. See '
             f'<a href="{p("security")}#cache">the session cache</a>.</p>'),
            ("ssign says “file already has a signature”.",
             f'<p>ssign does not replace an existing Authenticode signature: it stops on a PE file that is already '
             f'signed. Sign the file as it came out of the build.</p>'),
            ("Does ssign verify signatures?",
             f'<p>No. Check the result with <code>osslsigncode verify</code> or with <code>signtool</code> on Windows. '
             f'ssign\'s own release pipeline checks every signed file with <code>osslsigncode verify</code>.</p>'),
            ("Does it work with other certificate authorities or a hardware token?",
             f'<p>No. ssign signs only with a Certum SimplySign cloud certificate.</p>'),
            ("Does ssign run in a minimal Docker image?",
             f'<p>It needs no SimplySign software, but it checks HTTPS certificates through the operating system\'s '
             f'certificate store. The image must therefore contain CA certificates: a bare <code>scratch</code> '
             f'container has none.</p>'),
            ("SimplySign Desktop keeps looping on the login page.",
             f'<p>That is a SimplySign Desktop issue, recorded while the protocol was studied: version 2.9.10 gets an '
             f'HTTP 415 error in a tight loop when it lists the cards, so the card is never inserted and the login page '
             f'loops; version 2.9.14 speaks the current API. ssign does not use SimplySign Desktop at all. Details in '
             f'<a href="{PROTOCOL}">the protocol notes</a>.</p>'),
            ("Is ssign an official Certum tool?",
             f'<p>No. It is an independent open-source client for the SimplySign cloud, not affiliated with or '
             f'endorsed by Certum / Asseco.</p>'),
            ("Where can I ask a question or report a bug?",
             f'<p>On <a href="{DISCORD}">Discord</a> or in the <a href="{REPO}/issues">GitHub issues</a>.</p>'),
        ]
    return [
        ("Peut-on utiliser un certificat Certum SimplySign sous Linux sans SimplySign Desktop ?",
         f'<p>Oui. ssign parle lui-même au cloud SimplySign en HTTPS : il se connecte, récupère votre certificat et '
         f'demande la signature au cloud, sans SimplySign Desktop, sans interface graphique, sans conteneur et sans pile '
         f'PKCS#11. Il fonctionne sous Linux, macOS et Windows. Voir la <a href="{p("getting-started")}">prise en '
         f'main</a>.</p>'),
        ("Faut-il Windows pour signer un .exe Windows ?",
         f'<p>Non. La signature Authenticode, ce ne sont que des données : ssign hache le fichier, obtient la signature '
         f'RSA du cloud et construit lui-même la signature PKCS#7, sans aucune API Windows. La version Windows de ssign '
         f'est d\'ailleurs signée ainsi, depuis une machine Linux.</p>'),
        ("Peut-on signer dans GitHub Actions ou une autre CI ?",
         f'<p>Oui. Donnez à ssign <code>CERTUM_EMAIL</code> et la graine TOTP dans <code>CERTUM_OTP</code> : il calcule '
         f'le code à usage unique à chaque exécution. Gardez la graine dans un environnement protégé qui demande votre '
         f'accord : voir <a href="{p("github-actions")}">GitHub Actions</a>.</p>'),
        ("Quels types de fichiers peut-il signer ?",
         f'<p>La commande <code>ssign</code> signe les fichiers PE : <code>.exe</code>, <code>.dll</code>, '
         f'<code>.sys</code>, <code>.ocx</code>, <code>.cpl</code>. Pour les MSI, CAB, catalogues, APPX et scripts '
         f'PowerShell, utilisez le <a href="{p("pkcs11")}">module PKCS#11</a> avec osslsigncode. La signature MSI native '
         f'dans la commande elle-même est encore en cours.</p>'),
        ("Qu'est-ce que la graine TOTP, et faut-il la stocker ?",
         f'<p>C\'est le secret en base32 derrière l\'appli d\'authentification que vous avez configurée avec le QR code '
         f'SimplySign. Elle est à longue durée : avec elle et votre e-mail, n\'importe qui peut signer en votre nom '
         f'jusqu\'à ce que vous régénériez le QR code. Elle ne sert qu\'à l\'automatisation (<code>--otp</code>). Sur '
         f'votre propre machine, passez plutôt le code du moment avec <code>--token</code> : la graine ne quitte alors '
         f'jamais votre appli. Voir <a href="{p("security")}">Sécurité</a>.</p>'),
        ("La connexion échoue avec « no authorization code after login — wrong e-mail or OTP? »",
         f'<p>Certum n\'a pas accepté l\'e-mail et le code. Vérifiez l\'e-mail, et que le code est bien en cours de '
         f'validité : un code vaut environ 30 secondes et Certum ne l\'accepte qu\'une fois. Avec <code>--otp</code>, '
         f'ssign calcule le code à partir de l\'horloge du système : elle doit donc être à l\'heure.</p>'),
        ("Je signe plusieurs fichiers, ou je lance ssign plusieurs fois. Faut-il un nouveau code à chaque fois ?",
         f'<p>Non. Une seule connexion signe tous les fichiers passés sur la ligne de commande. La session est aussi '
         f'gardée en cache 20 minutes : les exécutions suivantes, et le module PKCS#11, la réutilisent sans nouveau code. '
         f'Voir <a href="{p("security")}#cache">le cache de session</a>.</p>'),
        ("ssign affiche « file already has a signature ».",
         f'<p>ssign ne remplace pas une signature Authenticode existante : il s\'arrête sur un fichier PE déjà signé. '
         f'Signez le fichier tel qu\'il sort de la compilation.</p>'),
        ("ssign vérifie-t-il les signatures ?",
         f'<p>Non. Vérifiez le résultat avec <code>osslsigncode verify</code>, ou avec <code>signtool</code> sous '
         f'Windows. La chaîne de publication de ssign contrôle elle-même chaque fichier signé avec '
         f'<code>osslsigncode verify</code>.</p>'),
        ("Fonctionne-t-il avec d'autres autorités de certification ou un jeton matériel ?",
         f'<p>Non. ssign signe uniquement avec un certificat cloud Certum SimplySign.</p>'),
        ("ssign fonctionne-t-il dans une image Docker minimale ?",
         f'<p>Il n\'a besoin d\'aucun logiciel SimplySign, mais il vérifie les certificats HTTPS via le magasin de '
         f'certificats du système. L\'image doit donc contenir les certificats des autorités : un conteneur '
         f'<code>scratch</code> nu n\'en a aucun.</p>'),
        ("SimplySign Desktop tourne en boucle sur la page de connexion.",
         f'<p>C\'est un problème de SimplySign Desktop, relevé pendant l\'étude du protocole : la version 2.9.10 reçoit '
         f'une erreur HTTP 415 en boucle quand elle liste les cartes, la carte n\'est donc jamais insérée et la page de '
         f'connexion tourne en boucle ; la version 2.9.14 parle l\'API actuelle. ssign n\'utilise pas du tout SimplySign '
         f'Desktop. Détails dans <a href="{PROTOCOL}">les notes sur le protocole</a> (en anglais).</p>'),
        ("ssign est-il un outil officiel de Certum ?",
         f'<p>Non. C\'est un client libre et indépendant pour le cloud SimplySign, sans lien avec Certum / Asseco ni '
         f'approuvé par eux.</p>'),
        ("Où poser une question ou signaler un bug ?",
         f'<p>Sur <a href="{DISCORD}">Discord</a> ou dans les <a href="{REPO}/issues">tickets GitHub</a>.</p>'),
    ]


# ---------------------------------------------------------------- content

def content(page, lang):
    p = lambda name: href(name, lang, lang)  # noqa: E731
    en = lang == "en"

    if page == "index":
        if en:
            return ("ssign – Certum SimplySign code signing on Linux, macOS and CI, without SimplySign Desktop",
                    "Sign Windows executables (Authenticode) with a Certum SimplySign cloud certificate from Linux, "
                    "macOS or Windows, over HTTPS, without SimplySign Desktop. Free CLI for CI and GitHub Actions.",
                    f"""
<section class="hero">
<p class="eyebrow">Certum SimplySign · Authenticode</p>
<h1>Sign Windows executables with Certum SimplySign, from Linux, macOS or Windows</h1>
<p class="lead">ssign is a free, open-source command-line tool that Authenticode-signs Windows binaries with your
Certum SimplySign cloud certificate. It talks to the SimplySign cloud over HTTPS by itself: no SimplySign Desktop, no
GUI, no container, no PKCS#11 stack. One command, on your own machine or in CI.</p>
{pre("ssign -e you@example.com -T 123456 app.exe")}
<p class="actions"><a class="btn big" href="{p('download')}">Download ssign</a>
<a class="btn big ghost" href="{p('getting-started')}">Get started</a></p>
</section>

<h2>The problem</h2>
<p>With a SimplySign certificate, the private key stays in Certum's cloud HSM (hardware security module); signing
happens remotely. Certum's client application, SimplySign Desktop, holds the login session and makes the calls to
the cloud. Its PKCS#11 module has no network code of its own: it only relays requests to the running, logged-in desktop
application. On a headless server or a CI runner, the workaround has been to run SimplySign Desktop in a container with
a virtual display (Xvnc) and p11-kit, as <a href="{CERTUM_CONTAINER}">certum-container</a> does.</p>

<h2>What ssign does instead</h2>
<p>Authenticode signing is just data: hash the file, have the cloud sign, wrap the RSA signature into a PKCS#7 blob.
ssign does every step itself, so a Linux laptop or an <code>ubuntu-latest</code> runner can sign a Windows binary:</p>
{flow("en")}

<div class="cards">
<div class="card"><h3>Get started</h3><p>Log in with a one-time code or a TOTP seed, sign one file or a whole
batch.</p><a class="more" href="{p('getting-started')}">Sign your first file →</a></div>
<div class="card"><h3>GitHub Actions</h3><p>A signing workflow, gated so that the repository owner approves every
run.</p><a class="more" href="{p('github-actions')}">Sign in CI →</a></div>
<div class="card"><h3>PKCS#11 module</h3><p>MSI, CAB, catalogs, APPX and PowerShell scripts through
osslsigncode.</p><a class="more" href="{p('pkcs11')}">Every format →</a></div>
<div class="card"><h3>Security</h3><p>What is sent where, what is cached on disk, and why the TOTP seed is a
long-lived secret.</p><a class="more" href="{p('security')}">How it works →</a></div>
</div>

<h2>What it signs</h2>
<div class="table"><table><thead><tr><th>Does</th><th>Does not (yet)</th></tr></thead><tbody>
<tr><td>Authenticode-signs <strong>PE</strong> files: <code>.exe</code>, <code>.dll</code>, <code>.sys</code>,
<code>.ocx</code>, <code>.cpl</code></td><td><strong>MSI / MSP / MSM</strong> in the <code>ssign</code> command
(work in progress; use the <a href="{p('pkcs11')}">PKCS#11 module</a>)</td></tr>
<tr><td>Embeds the <strong>full certificate chain</strong> (your certificate + the Certum intermediate)</td>
<td><strong>CAB</strong>, catalogs (<code>.cat</code>), PowerShell scripts, APPX/MSIX in the command itself (the module
covers them)</td></tr>
<tr><td>Adds an <strong>RFC 3161 timestamp</strong> (<code>time.certum.pl</code>)</td>
<td>Signing with anything other than a <strong>Certum SimplySign</strong> cloud certificate</td></tr>
<tr><td>Runs on <strong>Linux, macOS, Windows</strong>; signs many files with <strong>one login</strong></td>
<td><strong>Verifying</strong> signatures (use <code>signtool</code> or <code>osslsigncode</code>)</td></tr>
</tbody></table></div>
<p>It works end to end for PE files, proven in CI: ssign produces a valid Authenticode signature with the real Certum
cloud certificate, the full chain and an RFC 3161 timestamp. ssign's own Windows release is signed with ssign, from a
Linux runner.</p>

<h2>Runs on</h2>
<ul>
<li><strong>Linux</strong> (x86_64 and ARM 64-bit), <strong>macOS</strong> (Apple silicon and Intel) and
<strong>Windows</strong> (64-bit): <a href="{p('download')}">prebuilt downloads</a>.</li>
<li>Or with Rust installed: <code>cargo install ssign</code>.</li>
</ul>

<h2>Free software, built in the open</h2>
<p>ssign is written in Rust and released under the MIT licence. The source code, the releases and the issue tracker
are on <a href="{REPO}">GitHub</a>. Native support for more formats (MSI, CAB, catalogs, APPX/MSIX, scripts) is
welcome as contributions. Questions, bug reports or beta testing: join the <a href="{DISCORD}">Discord</a>.</p>
""")
        return ("ssign – signer un exécutable Windows sous Linux avec Certum SimplySign, sans SimplySign Desktop",
                "Signez vos exécutables Windows (Authenticode) avec un certificat cloud Certum SimplySign depuis Linux, "
                "macOS ou Windows, en HTTPS, sans SimplySign Desktop. Outil libre pour la CI et GitHub Actions.",
                f"""
<section class="hero">
<p class="eyebrow">Certum SimplySign · Authenticode</p>
<h1>Signez vos exécutables Windows avec Certum SimplySign, depuis Linux, macOS ou Windows</h1>
<p class="lead">ssign est un outil en ligne de commande libre et gratuit qui signe en Authenticode les binaires Windows
avec votre certificat cloud Certum SimplySign. Il parle lui-même au cloud SimplySign en HTTPS : sans SimplySign
Desktop, sans interface graphique, sans conteneur, sans pile PKCS#11. Une seule commande, sur votre machine ou en
CI.</p>
{pre("ssign -e vous@example.com -T 123456 app.exe")}
<p class="actions"><a class="btn big" href="{p('download')}">Télécharger ssign</a>
<a class="btn big ghost" href="{p('getting-started')}">Prise en main</a></p>
</section>

<h2>Le problème</h2>
<p>Avec un certificat SimplySign, la clé privée reste dans le HSM (module matériel de sécurité) du cloud Certum : la
signature se fait à distance. L'application cliente de Certum, SimplySign Desktop, détient la session de connexion et
se charge des appels au cloud. Son module PKCS#11 n'a aucun code réseau : il se contente de relayer les demandes vers
l'application de bureau, qui doit tourner et être connectée. Sur un serveur sans écran ou une machine de CI, le
contournement consistait à faire tourner SimplySign Desktop dans un conteneur avec un affichage virtuel (Xvnc) et p11-kit, comme le
fait <a href="{CERTUM_CONTAINER}">certum-container</a>.</p>

<h2>Ce que fait ssign à la place</h2>
<p>La signature Authenticode, ce ne sont que des données : hacher le fichier, faire signer par le cloud, emballer la
signature RSA dans un blob PKCS#7. ssign fait lui-même chaque étape, si bien qu'un portable Linux ou une machine
<code>ubuntu-latest</code> peut signer un binaire Windows :</p>
{flow("fr")}

<div class="cards">
<div class="card"><h3>Prise en main</h3><p>Connexion avec un code à usage unique ou une graine TOTP, signature d'un
fichier ou d'un lot entier.</p><a class="more" href="{p('getting-started')}">Signer un premier fichier →</a></div>
<div class="card"><h3>GitHub Actions</h3><p>Un workflow de signature verrouillé : le propriétaire du dépôt approuve
chaque exécution.</p><a class="more" href="{p('github-actions')}">Signer en CI →</a></div>
<div class="card"><h3>Module PKCS#11</h3><p>MSI, CAB, catalogues, APPX et scripts PowerShell via
osslsigncode.</p><a class="more" href="{p('pkcs11')}">Tous les formats →</a></div>
<div class="card"><h3>Sécurité</h3><p>Ce qui est envoyé et à qui, ce qui est gardé sur le disque, et pourquoi la graine
TOTP est un secret à longue durée.</p><a class="more" href="{p('security')}">Fonctionnement →</a></div>
</div>

<h2>Ce qu'il signe</h2>
<div class="table"><table><thead><tr><th>Fait</th><th>Ne fait pas (encore)</th></tr></thead><tbody>
<tr><td>Signe en Authenticode les fichiers <strong>PE</strong> : <code>.exe</code>, <code>.dll</code>,
<code>.sys</code>, <code>.ocx</code>, <code>.cpl</code></td><td>Les <strong>MSI / MSP / MSM</strong> dans la commande
<code>ssign</code> (en cours ; utilisez le <a href="{p('pkcs11')}">module PKCS#11</a>)</td></tr>
<tr><td>Intègre la <strong>chaîne de certificats complète</strong> (votre certificat + l'intermédiaire Certum)</td>
<td>Les <strong>CAB</strong>, catalogues (<code>.cat</code>), scripts PowerShell, APPX/MSIX dans la commande elle-même
(le module les couvre)</td></tr>
<tr><td>Ajoute un <strong>horodatage RFC 3161</strong> (<code>time.certum.pl</code>)</td>
<td>Signer avec autre chose qu'un certificat cloud <strong>Certum SimplySign</strong></td></tr>
<tr><td>Tourne sous <strong>Linux, macOS, Windows</strong> ; signe un lot de fichiers avec <strong>une seule
connexion</strong></td><td><strong>Vérifier</strong> les signatures (utilisez <code>signtool</code> ou
<code>osslsigncode</code>)</td></tr>
</tbody></table></div>
<p>Il fonctionne de bout en bout pour les fichiers PE, prouvé en CI : ssign produit une signature Authenticode valide
avec le vrai certificat cloud Certum, la chaîne complète et un horodatage RFC 3161. La version Windows de ssign est
elle-même signée avec ssign, depuis une machine Linux.</p>

<h2>Fonctionne sous</h2>
<ul>
<li><strong>Linux</strong> (x86_64 et ARM 64 bits), <strong>macOS</strong> (Apple silicon et Intel) et
<strong>Windows</strong> (64 bits) : <a href="{p('download')}">binaires prêts à l'emploi</a>.</li>
<li>Ou, si Rust est installé : <code>cargo install ssign</code>.</li>
</ul>

<h2>Un logiciel libre, développé ouvertement</h2>
<p>ssign est écrit en Rust et publié sous licence MIT. Le code source, les versions publiées et les tickets sont sur
<a href="{REPO}">GitHub</a>. Les contributions pour gérer nativement d'autres formats (MSI, CAB, catalogues, APPX/MSIX,
scripts) sont les bienvenues. Questions, bugs ou tests des bêtas : rejoignez le <a href="{DISCORD}">Discord</a>.</p>
""")

    if page == "download":
        if en:
            return ("Download ssign for Linux, macOS and Windows – Certum SimplySign signing tool",
                    "Download ssign, the free command-line tool that signs Windows executables with a Certum SimplySign "
                    "cloud certificate: Linux x86_64 and ARM64, macOS Apple silicon and Intel, Windows. PKCS#11 module too.",
                    f"""
<h1>Download ssign</h1>
<p class="lead">ssign is a single program file: download the archive for your system and extract it. These links
always point to the latest release.</p>
{downloads("en", False)}
<p>Release notes and older versions: <a href="{REPO}/releases">all releases on GitHub</a>.</p>

<h2>Install</h2>
<ul>
<li><strong>Linux and macOS</strong>: extract the archive and put <code>ssign</code> on your <code>PATH</code> (use the
archive name for your system):
{pre(INSTALL_UNIX)}</li>
<li><strong>Windows</strong>: extract the zip; it contains <code>ssign.exe</code>.</li>
</ul>
<p>The Windows files (<code>ssign.exe</code> and <code>ssign_pkcs11.dll</code>) are Authenticode-signed with ssign
itself during the release, from a Linux runner, and checked with <code>osslsigncode verify</code>. The macOS files
are signed and notarized with Apple, and built for macOS 11 or later.</p>

<h2 id="pkcs11">PKCS#11 module</h2>
<p>To sign MSI, CAB, catalogs, APPX or PowerShell scripts with osslsigncode, download the module for your system.
How to use it: <a href="{p('pkcs11')}">PKCS#11 and osslsigncode</a>.</p>
{downloads("en", True)}

<h2>With Cargo</h2>
<p>If Rust is installed, the command is on crates.io:</p>
{pre("cargo install ssign")}
<p>The PKCS#11 module is not on crates.io: it is a shared library, which <code>cargo install</code> cannot install.
Take the prebuilt module above, or build it from a clone of the repository:</p>
{pre("cargo build -p ssign-pkcs11 --release   # → target/release/libssign_pkcs11.so")}

<h2>What you need</h2>
<ul>
<li><strong>A Certum SimplySign cloud code-signing certificate</strong>, the account e-mail, and the authenticator app
you set up from the SimplySign QR code.</li>
<li><strong>Network access</strong> to <code>cloudsign.webnotarius.pl</code> (HTTPS) and to the timestamp server,
<code>http://time.certum.pl/</code> by default.</li>
<li><strong>A system certificate store</strong>: ssign checks HTTPS certificates through the operating system's
trust store, so a bare container image without CA certificates will not work.</li>
</ul>
<p>Next step: <a href="{p('getting-started')}">sign your first file</a>.</p>
""")
        return ("Télécharger ssign pour Linux, macOS et Windows – outil de signature Certum SimplySign",
                "Téléchargez ssign, l'outil libre en ligne de commande qui signe les exécutables Windows avec un certificat "
                "cloud Certum SimplySign : Linux x86_64 et ARM64, macOS Apple silicon et Intel, Windows. Module PKCS#11 inclus.",
                f"""
<h1>Télécharger ssign</h1>
<p class="lead">ssign tient en un seul fichier programme : téléchargez l'archive de votre système et décompressez-la.
Ces liens mènent toujours à la dernière version.</p>
{downloads("fr", False)}
<p>Notes de version et anciennes versions : <a href="{REPO}/releases">toutes les versions sur GitHub</a>.</p>

<h2>Installer</h2>
<ul>
<li><strong>Linux et macOS</strong> : décompressez l'archive et placez <code>ssign</code> dans votre
<code>PATH</code> (avec le nom d'archive de votre système) :
{pre(INSTALL_UNIX)}</li>
<li><strong>Windows</strong> : décompressez le zip ; il contient <code>ssign.exe</code>.</li>
</ul>
<p>Les fichiers Windows (<code>ssign.exe</code> et <code>ssign_pkcs11.dll</code>) sont signés en Authenticode avec ssign
lui-même pendant la publication, depuis une machine Linux, puis contrôlés avec <code>osslsigncode verify</code>. Les
fichiers macOS sont signés et notariés auprès d'Apple, et compilés pour macOS 11 ou plus récent.</p>

<h2 id="pkcs11">Module PKCS#11</h2>
<p>Pour signer des MSI, CAB, catalogues, APPX ou scripts PowerShell avec osslsigncode, téléchargez le module de votre
système. Mode d'emploi : <a href="{p('pkcs11')}">PKCS#11 et osslsigncode</a>.</p>
{downloads("fr", True)}

<h2>Avec Cargo</h2>
<p>Si Rust est installé, la commande est disponible sur crates.io :</p>
{pre("cargo install ssign")}
<p>Le module PKCS#11 n'est pas sur crates.io : c'est une bibliothèque partagée, que <code>cargo install</code> ne sait
pas installer. Prenez le module prêt à l'emploi ci-dessus, ou compilez-le depuis un clone du dépôt :</p>
{pre("cargo build -p ssign-pkcs11 --release   # → target/release/libssign_pkcs11.so")}

<h2>Ce qu'il faut</h2>
<ul>
<li><strong>Un certificat de signature de code cloud Certum SimplySign</strong>, l'e-mail du compte et l'appli
d'authentification configurée avec le QR code SimplySign.</li>
<li><strong>Un accès réseau</strong> à <code>cloudsign.webnotarius.pl</code> (HTTPS) et au serveur d'horodatage,
<code>http://time.certum.pl/</code> par défaut.</li>
<li><strong>Un magasin de certificats système</strong> : ssign vérifie les certificats HTTPS via le magasin du système
d'exploitation, donc une image de conteneur nue, sans certificats d'autorités, ne fonctionnera pas.</li>
</ul>
<p>Étape suivante : <a href="{p('getting-started')}">signer votre premier fichier</a>.</p>
""")

    if page == "getting-started":
        if en:
            return ("Sign a Windows exe on Linux with Certum SimplySign – ssign getting started",
                    "How to sign a Windows .exe or .dll on Linux or macOS with a Certum SimplySign cloud certificate: "
                    "one-time code or TOTP seed, batch signing, all ssign options and environment variables.",
                    f"""
<h1>Sign a Windows executable on Linux with Certum SimplySign</h1>
<p class="lead">The same commands work on Linux, macOS and Windows. You need your Certum account e-mail and your
authenticator app. <a href="{p('download')}">Download ssign</a> first if you have not already.</p>

<h2>1. Choose how to log in</h2>
<p>The SimplySign cloud login takes your e-mail and a 6-digit one-time code, not a password. Give ssign exactly one
of these:</p>
<div class="table"><table class="modes"><thead><tr><th>Mode</th><th>Option</th><th>When</th></tr></thead><tbody>
<tr><td><strong>Manual</strong></td><td><code>-T</code>, <code>--token &lt;CODE&gt;</code></td><td>On your own machine: read the
<strong>current</strong> code from your authenticator app and pass it.</td></tr>
<tr><td><strong>Automatic</strong></td><td><code>-O</code>, <code>--otp &lt;SEED&gt;</code></td><td>CI and scripts: give your TOTP
<strong>seed</strong> once, and ssign computes the 6-digit code on every run.</td></tr>
</tbody></table></div>
<div class="note"><strong>The seed is a long-lived secret.</strong> With your seed and your e-mail, anyone can sign code
as you until you re-issue the SimplySign QR code. Never pass it as a command-line argument; use the
<code>CERTUM_OTP</code> environment variable, and prefer <code>--token</code> when you sign by hand.
<a href="{p('security')}">Read the security notes</a>.</div>

<h2>2. Sign</h2>
{pre(SIGN_EN)}
<p>Files are signed <strong>in place</strong> by default. <code>--backup</code> keeps the original as
<code>&lt;file&gt;.orig</code>; <code>-o &lt;DIR&gt;</code> writes the signed files to another folder instead. ssign
prints <code>signed &lt;file&gt;</code> for each file; add <code>-v</code> to see each step.</p>

<h2>3. Check the result</h2>
<p>ssign does not verify signatures. Use <code>osslsigncode verify app.exe</code>, or <code>signtool</code> on
Windows.</p>

<h2 id="options">All options</h2>
{options_table("en")}
<p>Only the e-mail, the seed and the code can come from environment variables. Prefer them for secrets: a value passed
on the command line is visible in your shell history and in the process list. Passing both <code>--otp</code> and
<code>--token</code> is an error.</p>

<h2>The seed: base32 or otpauth:// URI</h2>
<p><code>--otp</code> accepts a bare base32 secret or a full <code>otpauth://</code> URI. With a bare secret, ssign uses
SimplySign's settings: SHA-256 (not the SHA-1 default of most TOTP libraries), 6 digits, 30 seconds. With a URI, the
algorithm, digits and period are read from the URI. The code is computed from the system clock.</p>

<h2>One login for many files</h2>
<p>ssign logs in once per run and signs every file you list with that session. It also saves the session for 20
minutes, so the next runs within that time, and the <a href="{p('pkcs11')}">PKCS#11 module</a>, sign without a new code.
That matters because Certum accepts each code only once. Where the session is stored and what that means:
<a href="{p('security')}#cache">the session cache</a>.</p>

<h2>Good to know</h2>
<ul>
<li>ssign will not sign a PE file that already carries a signature (“file already has a signature”).</li>
<li>With <code>--backup</code>, an existing <code>.orig</code> file is never overwritten: the run stops and the file is
left as it was.</li>
<li>The signed file is written to a temporary file and then swapped in, and it keeps the permissions of the file it
replaces.</li>
<li><code>-n</code> and <code>-u</code> embed a description and an information URL in the signature.</li>
</ul>
<p>Signing in a pipeline? Continue with <a href="{p('github-actions')}">GitHub Actions</a>.</p>
""")
        return ("Signer un exécutable Windows sous Linux avec Certum SimplySign – prise en main de ssign",
                "Comment signer un .exe ou une .dll Windows sous Linux ou macOS avec un certificat cloud Certum SimplySign : "
                "code à usage unique ou graine TOTP, signature par lots, options et variables d'environnement de ssign.",
                f"""
<h1>Signer un exécutable Windows sous Linux avec Certum SimplySign</h1>
<p class="lead">Les mêmes commandes fonctionnent sous Linux, macOS et Windows. Il vous faut l'e-mail de votre compte
Certum et votre appli d'authentification. <a href="{p('download')}">Téléchargez ssign</a> d'abord si ce n'est pas
fait.</p>

<h2>1. Choisir le mode de connexion</h2>
<p>La connexion au cloud SimplySign se fait avec votre e-mail et un code à usage unique à 6 chiffres, pas avec un mot
de passe. Donnez à ssign exactement l'un des deux :</p>
<div class="table"><table class="modes"><thead><tr><th>Mode</th><th>Option</th><th>Quand</th></tr></thead><tbody>
<tr><td><strong>Manuel</strong></td><td><code>-T</code>, <code>--token &lt;CODE&gt;</code></td><td>Sur votre machine : lisez le code
<strong>du moment</strong> dans votre appli d'authentification et passez-le.</td></tr>
<tr><td><strong>Automatique</strong></td><td><code>-O</code>, <code>--otp &lt;SEED&gt;</code></td><td>CI et scripts : fournissez une
fois votre <strong>graine</strong> TOTP (seed), et ssign calcule le code à 6 chiffres à chaque exécution.</td></tr>
</tbody></table></div>
<div class="note"><strong>La graine est un secret à longue durée.</strong> Avec votre graine et votre e-mail, n'importe
qui peut signer du code en votre nom jusqu'à ce que vous régénériez le QR code SimplySign. Ne la passez jamais en
argument de ligne de commande : utilisez la variable d'environnement <code>CERTUM_OTP</code>, et préférez
<code>--token</code> quand vous signez à la main. <a href="{p('security')}">Lire les notes de sécurité</a>.</div>

<h2>2. Signer</h2>
{pre(SIGN_FR)}
<p>Les fichiers sont signés <strong>sur place</strong> par défaut. <code>--backup</code> garde l'original sous le nom
<code>&lt;fichier&gt;.orig</code> ; <code>-o &lt;DIR&gt;</code> écrit plutôt les fichiers signés dans un autre dossier.
ssign affiche <code>signed &lt;fichier&gt;</code> pour chaque fichier ; ajoutez <code>-v</code> pour voir chaque
étape.</p>

<h2>3. Vérifier le résultat</h2>
<p>ssign ne vérifie pas les signatures. Utilisez <code>osslsigncode verify app.exe</code>, ou <code>signtool</code>
sous Windows.</p>

<h2 id="options">Toutes les options</h2>
{options_table("fr")}
<p>Seuls l'e-mail, la graine et le code peuvent venir de variables d'environnement. Préférez-les pour les secrets : une
valeur passée en ligne de commande est visible dans l'historique du shell et dans la liste des processus. Passer à la
fois <code>--otp</code> et <code>--token</code> est une erreur.</p>

<h2>La graine : base32 ou URI otpauth://</h2>
<p><code>--otp</code> accepte un secret base32 brut ou une URI <code>otpauth://</code> complète. Avec un secret brut,
ssign applique les réglages de SimplySign : SHA-256 (et non le SHA-1 par défaut de la plupart des bibliothèques TOTP),
6 chiffres, 30 secondes. Avec une URI, l'algorithme, le nombre de chiffres et la période sont lus dans l'URI. Le code
est calculé à partir de l'horloge du système.</p>

<h2>Une connexion pour de nombreux fichiers</h2>
<p>ssign se connecte une fois par exécution et signe tous les fichiers listés avec cette session. Il garde aussi la
session pendant 20 minutes : les exécutions suivantes dans ce délai, ainsi que le <a href="{p('pkcs11')}">module
PKCS#11</a>, signent sans nouveau code. C'est important, car Certum n'accepte chaque code qu'une seule fois. Où la
session est stockée, et ce que cela implique : <a href="{p('security')}#cache">le cache de session</a>.</p>

<h2>Bon à savoir</h2>
<ul>
<li>ssign refuse de signer un fichier PE qui porte déjà une signature (« file already has a signature »).</li>
<li>Avec <code>--backup</code>, un fichier <code>.orig</code> existant n'est jamais écrasé : l'exécution s'arrête et le
fichier reste intact.</li>
<li>Le fichier signé est d'abord écrit dans un fichier temporaire puis mis en place d'un coup, et il garde les
permissions du fichier qu'il remplace.</li>
<li><code>-n</code> et <code>-u</code> intègrent une description et une URL d'information dans la signature.</li>
</ul>
<p>Vous signez dans un pipeline ? Continuez avec <a href="{p('github-actions')}">GitHub Actions</a>.</p>
""")

    if page == "github-actions":
        if en:
            return ("Authenticode code signing in GitHub Actions with Certum SimplySign – ssign",
                    "Sign Windows executables with a Certum SimplySign cloud certificate in GitHub Actions, on an "
                    "ubuntu-latest runner, with a protected environment so the owner approves every signing run.",
                    f"""
<h1>Code signing in GitHub Actions with Certum SimplySign</h1>
<p class="lead">ssign runs on a Linux runner and signs Windows binaries there: no Windows runner, no SimplySign Desktop,
no container. The account e-mail and the TOTP seed come from environment secrets.</p>

<h2>A signing workflow</h2>
{pre(WORKFLOW_EN)}
<p><code>CERTUM_OTP</code> holds your TOTP <strong>seed</strong>, the long-lived secret that lets anyone sign as you.
Store it as described below, not as a plain repository secret.</p>

<h2 id="approval">Require the owner's approval for every signing run</h2>
<p>Signing uses your certificate and, if mishandled, can expose the seed. Gate it behind a <strong>GitHub
Environment</strong>, so that the repository owner must approve every signing run before the job can even read the
secrets:</p>
<ol>
<li><strong>Settings → Environments → New environment</strong>, name it <code>signing</code>.</li>
<li>Add a <strong>Deployment protection rule → Required reviewers</strong>, and add yourself (the owner). Any job that
targets this environment now <strong>pauses for your approval</strong>.</li>
<li>Store <code>CERTUM_EMAIL</code> and <code>CERTUM_OTP</code> as <strong>environment secrets</strong> of
<code>signing</code> (not repository secrets). They are readable <strong>only</strong> inside an approved run of a job
that declares <code>environment: signing</code>.</li>
<li>In the workflow, the signing job declares <code>environment: signing</code>, as above.</li>
</ol>
<p>Result: a pull request, even a malicious one, <strong>cannot</strong> trigger a signature or read the seed; every
run waits for the owner's click. Also keep the signing job on <code>workflow_dispatch</code> or protected-branch
pushes, <strong>never</strong> on <code>pull_request</code> from forks.</p>

<h2 id="release">In a release pipeline</h2>
<p>Make signing a <strong>job in the same workflow</strong> as the build and the release, gated by
<code>environment: signing</code>, with the release job listing it in <code>needs:</code>. A tag then becomes
<em>build → approve → signed release</em>. Do not rely on a separate workflow triggered by
<code>release: published</code>: a release created by the built-in <code>GITHUB_TOKEN</code> <strong>does not</strong>
trigger other workflows.</p>

<h2>A real example: ssign signs its own Windows release</h2>
<p>ssign's release workflow does exactly this. On each version tag, a job on <code>ubuntu-latest</code> takes the Linux
<code>ssign</code> binary built earlier in the same run, waits for approval through the <code>signing</code>
environment, signs the Windows <code>ssign.exe</code> and <code>ssign_pkcs11.dll</code> with a single Certum login,
then checks both with <code>osslsigncode verify</code>. The release job waits for it. Abridged:</p>
{pre(SELF_SIGN)}
<p>The full file: <a href="{CI_FILE}">.github/workflows/ci.yml</a>.</p>

<h2>Several files, one login</h2>
<p>Pass every file to one <code>ssign</code> call, as above: it logs in once for the whole batch. If a later step signs
other formats with the <a href="{p('pkcs11')}">PKCS#11 module</a> in the same job, the module reuses the cached session
instead of logging in again (see <a href="{p('security')}#cache">the session cache</a>).</p>
""")
        return ("Signature Authenticode dans GitHub Actions avec Certum SimplySign – ssign",
                "Signez des exécutables Windows avec un certificat cloud Certum SimplySign dans GitHub Actions, sur une "
                "machine ubuntu-latest, avec un environnement protégé : le propriétaire approuve chaque signature.",
                f"""
<h1>Signature de code dans GitHub Actions avec Certum SimplySign</h1>
<p class="lead">ssign tourne sur une machine Linux et y signe les binaires Windows : pas de machine Windows, pas de
SimplySign Desktop, pas de conteneur. L'e-mail du compte et la graine TOTP viennent de secrets d'environnement.</p>

<h2>Un workflow de signature</h2>
{pre(WORKFLOW_FR)}
<p><code>CERTUM_OTP</code> contient votre <strong>graine</strong> TOTP, le secret à longue durée qui permet de signer
en votre nom. Stockez-la comme décrit ci-dessous, pas comme un simple secret de dépôt.</p>

<h2 id="approval">Exiger l'accord du propriétaire pour chaque signature</h2>
<p>Signer engage votre certificat et, mal géré, peut exposer la graine. Verrouillez la signature derrière un
<strong>Environment GitHub</strong>, pour que le propriétaire du dépôt approuve chaque exécution avant même que le job
ne puisse lire les secrets :</p>
<ol>
<li><strong>Settings → Environments → New environment</strong>, nommez-le <code>signing</code>.</li>
<li>Ajoutez une règle <strong>Deployment protection rule → Required reviewers</strong>, et ajoutez-vous (le
propriétaire). Tout job visant cet environnement <strong>se met en pause en attendant votre approbation</strong>.</li>
<li>Stockez <code>CERTUM_EMAIL</code> et <code>CERTUM_OTP</code> comme <strong>secrets d'environnement</strong> de
<code>signing</code> (pas des secrets de dépôt). Ils ne sont lisibles <strong>que</strong> dans une exécution approuvée
d'un job qui déclare <code>environment: signing</code>.</li>
<li>Dans le workflow, le job de signature déclare <code>environment: signing</code>, comme ci-dessus.</li>
</ol>
<p>Résultat : une pull request, même malveillante, <strong>ne peut pas</strong> déclencher une signature ni lire la
graine ; chaque exécution attend le clic du propriétaire. Gardez aussi le job de signature sur
<code>workflow_dispatch</code> ou sur des pushes de branches protégées, <strong>jamais</strong> sur
<code>pull_request</code> depuis un fork.</p>

<h2 id="release">Dans un pipeline de publication</h2>
<p>Faites de la signature un <strong>job du même workflow</strong> que la compilation et la publication, verrouillé
par <code>environment: signing</code>, et que le job de publication liste dans <code>needs:</code>. Un tag devient
alors <em>compilation → approbation → version signée</em>. Ne comptez pas sur un workflow séparé déclenché par
<code>release: published</code> : une release créée par le <code>GITHUB_TOKEN</code> intégré <strong>ne déclenche
pas</strong> d'autre workflow.</p>

<h2>Un exemple réel : ssign signe sa propre version Windows</h2>
<p>Le workflow de publication de ssign fait exactement cela. À chaque tag de version, un job sur
<code>ubuntu-latest</code> reprend le binaire Linux <code>ssign</code> compilé plus tôt dans la même exécution, attend
l'approbation via l'environnement <code>signing</code>, signe <code>ssign.exe</code> et <code>ssign_pkcs11.dll</code>
pour Windows avec une seule connexion Certum, puis contrôle les deux avec <code>osslsigncode verify</code>. Le job de
publication l'attend. Extrait :</p>
{pre(SELF_SIGN)}
<p>Le fichier complet : <a href="{CI_FILE}">.github/workflows/ci.yml</a>.</p>

<h2>Plusieurs fichiers, une connexion</h2>
<p>Passez tous les fichiers au même appel de <code>ssign</code>, comme ci-dessus : il se connecte une seule fois pour
tout le lot. Si une étape suivante du même job signe d'autres formats avec le <a href="{p('pkcs11')}">module
PKCS#11</a>, le module réutilise la session en cache au lieu de se reconnecter (voir
<a href="{p('security')}#cache">le cache de session</a>).</p>
""")

    if page == "pkcs11":
        if en:
            return ("osslsigncode PKCS#11 module for Certum SimplySign: sign MSI, CAB, scripts – ssign",
                    "ssign-pkcs11 exposes your Certum SimplySign cloud key to osslsigncode through PKCS#11, to sign MSI, "
                    "CAB, catalogs, APPX and PowerShell scripts on Linux or macOS, without SimplySign Desktop.",
                    f"""
<h1>Sign every format: the PKCS#11 module for osslsigncode</h1>
<p class="lead">The <code>ssign</code> command signs PE files (<code>.exe</code>, <code>.dll</code>, <code>.sys</code>…).
For every other Authenticode format (MSI, CAB, catalogs, APPX, PowerShell), ssign also ships a PKCS#11 module,
<code>ssign-pkcs11</code>, that hands your Certum cloud key to <a href="{OSSLSIGNCODE}">osslsigncode</a>, which already
knows how to hash and package them all. Still no SimplySign Desktop, no p11-kit, no smart card: the module talks to the
cloud over HTTPS like the rest of ssign.</p>

<h2>1. Get the module</h2>
<ul>
<li>Download it from the <a href="{p('download')}#pkcs11">download page</a>: <code>libssign_pkcs11.so</code> on Linux,
<code>libssign_pkcs11.dylib</code> on macOS, <code>ssign_pkcs11.dll</code> on Windows.</li>
<li>Or build it from a clone of the repository: <code>cargo build -p ssign-pkcs11 --release</code>.</li>
</ul>

<h2>2. Install osslsigncode</h2>
<p>osslsigncode needs either the OpenSSL PKCS#11 provider or the libp11 engine: it loads <code>pkcs11prov</code> if
present and falls back to the engine. Both work with the module. On Debian or Ubuntu:</p>
{pre(APT)}

<h2>3. Get the Certum intermediate certificate</h2>
<p>The <code>-ac</code> option embeds the Certum “Code Signing 2021 CA” intermediate so that the chain verifies. The
repository ships it in DER form as <a href="{INTERMEDIATE}"><code>ssign-core/src/certs/ccsca2021.der</code></a>;
convert it to PEM with OpenSSL:</p>
{pre(INTER_PEM)}

<h2>4. Sign</h2>
{pre(OSSL_EN)}
<p>Use the path of the module you downloaded or built. The module reads the same <code>CERTUM_EMAIL</code> and
<code>CERTUM_OTP</code> (or <code>CERTUM_TOKEN</code>, a current 6-digit code) as the command.</p>
<p>The module presents a single certificate and a single private key, both labelled
<code>Certum SimplySign (ssign)</code>, so <code>pkcs11:type=cert</code> and <code>pkcs11:type=private</code> are enough.
The repository's test script names them by label:</p>
{pre(LABEL_URIS)}

<h2>Many files, one code</h2>
<p>osslsigncode reloads the module for every file, and Certum accepts each code only once. The module therefore
<strong>caches the cloud session</strong> (the same cache as the <code>ssign</code> command), so signing many files in a
row needs only one code. You can sign your PE files with <code>ssign</code>, then your MSI with osslsigncode, with a
single login. See <a href="{p('security')}#cache">the session cache</a>.</p>

<h2>Tested end to end</h2>
<p><a href="{TEST_SCRIPT}"><code>ssign-pkcs11/tests/sign-all-formats.sh</code></a> signs and verifies one file of each
of these formats through the module and osslsigncode: <code>.exe</code>, <code>.dll</code>, <code>.msi</code> and
<code>.ps1</code>. CAB, CAT and APPX work too once you give it a sample file, since osslsigncode signs them; the script
just does not generate them. From a clone of the repository, with the module built:</p>
{pre(SMOKE)}

<h2>Limits</h2>
<ul>
<li>SHA-256 with RSA PKCS#1 v1.5 only: pass <code>-h sha256</code>.</li>
<li>The module signs; it cannot generate keys and does not verify signatures.</li>
</ul>
""")
        return ("Module PKCS#11 osslsigncode pour Certum SimplySign : signer MSI, CAB, scripts – ssign",
                "ssign-pkcs11 présente votre clé cloud Certum SimplySign à osslsigncode via PKCS#11, pour signer MSI, CAB, "
                "catalogues, APPX et scripts PowerShell sous Linux ou macOS, sans SimplySign Desktop.",
                f"""
<h1>Signer tous les formats : le module PKCS#11 pour osslsigncode</h1>
<p class="lead">La commande <code>ssign</code> signe les fichiers PE (<code>.exe</code>, <code>.dll</code>,
<code>.sys</code>…). Pour tous les autres formats Authenticode (MSI, CAB, catalogues, APPX, PowerShell), ssign fournit
aussi un module PKCS#11, <code>ssign-pkcs11</code>, qui présente votre clé cloud Certum à
<a href="{OSSLSIGNCODE}">osslsigncode</a>, lequel sait déjà tous les hacher et les emballer. Toujours sans SimplySign
Desktop, sans p11-kit, sans carte à puce : le module parle au cloud en HTTPS comme le reste de ssign.</p>

<h2>1. Obtenir le module</h2>
<ul>
<li>Téléchargez-le depuis la <a href="{p('download')}#pkcs11">page de téléchargement</a> :
<code>libssign_pkcs11.so</code> sous Linux, <code>libssign_pkcs11.dylib</code> sous macOS,
<code>ssign_pkcs11.dll</code> sous Windows.</li>
<li>Ou compilez-le depuis un clone du dépôt : <code>cargo build -p ssign-pkcs11 --release</code>.</li>
</ul>

<h2>2. Installer osslsigncode</h2>
<p>osslsigncode a besoin soit du fournisseur (provider) PKCS#11 d'OpenSSL, soit du moteur (engine) libp11 : il charge
<code>pkcs11prov</code> s'il est présent, et se rabat sinon sur le moteur. Les deux fonctionnent avec le module. Sous
Debian ou Ubuntu :</p>
{pre(APT)}

<h2>3. Récupérer le certificat intermédiaire Certum</h2>
<p>L'option <code>-ac</code> intègre l'intermédiaire Certum « Code Signing 2021 CA » pour que la chaîne se vérifie. Le
dépôt le fournit au format DER dans <a href="{INTERMEDIATE}"><code>ssign-core/src/certs/ccsca2021.der</code></a> ;
convertissez-le en PEM avec OpenSSL :</p>
{pre(INTER_PEM)}

<h2>4. Signer</h2>
{pre(OSSL_FR)}
<p>Indiquez le chemin du module téléchargé ou compilé. Le module lit les mêmes <code>CERTUM_EMAIL</code> et
<code>CERTUM_OTP</code> (ou <code>CERTUM_TOKEN</code>, un code à 6 chiffres en cours de validité) que la commande.</p>
<p>Le module présente un seul certificat et une seule clé privée, tous deux nommés
<code>Certum SimplySign (ssign)</code> : <code>pkcs11:type=cert</code> et <code>pkcs11:type=private</code> suffisent donc.
Le script de test du dépôt les désigne par leur nom :</p>
{pre(LABEL_URIS)}

<h2>Plusieurs fichiers, un seul code</h2>
<p>osslsigncode recharge le module pour chaque fichier, et Certum n'accepte chaque code qu'une fois. Le module
<strong>garde donc la session cloud en cache</strong> (le même cache que la commande <code>ssign</code>) : signer de
nombreux fichiers d'affilée ne demande qu'un seul code. Vous pouvez signer vos fichiers PE avec <code>ssign</code>, puis
votre MSI avec osslsigncode, avec une seule connexion. Voir <a href="{p('security')}#cache">le cache de session</a>.</p>

<h2>Testé de bout en bout</h2>
<p><a href="{TEST_SCRIPT}"><code>ssign-pkcs11/tests/sign-all-formats.sh</code></a> signe et vérifie un fichier de chacun
de ces formats via le module et osslsigncode : <code>.exe</code>, <code>.dll</code>, <code>.msi</code> et
<code>.ps1</code>. CAB, CAT et APPX fonctionnent aussi dès qu'on lui fournit un fichier d'exemple, puisque osslsigncode
les signe ; le script ne les génère simplement pas. Depuis un clone du dépôt, module compilé :</p>
{pre(SMOKE)}

<h2>Limites</h2>
<ul>
<li>SHA-256 avec RSA PKCS#1 v1.5 uniquement : passez <code>-h sha256</code>.</li>
<li>Le module signe ; il ne génère pas de clés et ne vérifie pas les signatures.</li>
</ul>
""")

    if page == "security":
        if en:
            return ("How ssign talks to the Certum SimplySign cloud: protocol, secrets and session cache",
                    "What ssign sends to the Certum SimplySign cloud and the timestamp server, why the TOTP seed is a "
                    "long-lived secret, where the session token is cached, and how the SimplySign protocol works.",
                    f"""
<h1>How ssign works, and what it does with your secrets</h1>
<p class="lead">ssign is an independent client for the SimplySign cloud signing service. Here is what leaves your
machine, what is kept on disk, and what to protect.</p>

<h2>What is sent where</h2>
<div class="table"><table><thead><tr><th>Destination</th><th>What ssign sends</th></tr></thead><tbody>
<tr><td><code>cloudsign.webnotarius.pl</code><br><span class="muted">HTTPS</span></td><td><ul>
<li>Login: your e-mail and the current 6-digit code, plus the OAuth client identifiers of the SimplySign web login.
These identifiers are application-level constants, identical for every SimplySign Desktop user, not your secret.</li>
<li>Then, with the bearer token it received: the request for your card and certificate, and for each signature a
SHA-256 digest computed on your machine together with your signing certificate.</li></ul></td></tr>
<tr><td>Timestamp server<br><span class="muted"><code>http://time.certum.pl/</code> by default, changed with
<code>--timestamp-url</code></span></td><td>An RFC 3161 request carrying the SHA-256 hash of the signature.</td></tr>
<tr><td>Nobody</td><td>Your files, which are hashed locally, and your TOTP seed, from which the code is computed
locally.</td></tr>
</tbody></table></div>
<p>HTTPS certificates are checked through the operating system's trust store.</p>

<h2>The login and the key</h2>
<ul>
<li>The login is an OAuth 2.0 authorization-code flow through Certum's CAS identity provider. The credentials are
the e-mail and the 6-digit code; no account password is involved.</li>
<li>It returns a bearer token valid for about 30 minutes. The SimplySign card needs no PIN
(<code>pinrequired: false</code>): the bearer token is the only control.</li>
<li>The key is RSA-4096 and the private key stays in the cloud HSM. ssign only receives signatures.</li>
</ul>

<h2 id="seed">The TOTP seed is a long-lived secret</h2>
<p><code>-O/--otp</code> (environment variable <code>CERTUM_OTP</code>) is your TOTP seed, the base32 secret behind your
authenticator. <strong>It is long-lived</strong>: anyone who has it <em>and</em> your e-mail can sign code as you,
indefinitely, until you re-issue the SimplySign QR code. Treat it like a private key.</p>
<ul>
<li><strong>Never</strong> pass it as a command-line argument: it lands in your shell history and in the process list.
Use the environment variable.</li>
<li>Prefer <strong><code>-T/--token</code></strong> (a one-shot 6-digit code) for local, manual signing, so the seed
never leaves your authenticator app.</li>
<li>In CI, store it as a <strong>protected environment secret with required reviewers</strong>
(<a href="{p('github-actions')}#approval">how</a>), not as a plain repository secret.</li>
<li>If it ever leaks, <strong>rotate it</strong>: re-issue the QR code from Certum.</li>
</ul>
<p>The account e-mail is not sensitive. The 6-digit code expires in about 30 seconds and is low-risk.</p>
<p>In memory, the command keeps the seed or code in a buffer that is wiped when it is no longer needed. That cannot undo
an exposure that happens before ssign starts: a value passed as <code>--otp</code> is visible in
<code>/proc/&lt;pid&gt;/cmdline</code>, and one passed through <code>CERTUM_OTP</code> in
<code>/proc/&lt;pid&gt;/environ</code>.</p>

<h2 id="cache">The session cache</h2>
<p>To avoid a second login (Certum accepts each code only once), the <code>ssign</code> command and the PKCS#11 module
save the session after logging in, and reuse it on the next runs.</p>
<ul>
<li><strong>Where</strong>: <code>$XDG_RUNTIME_DIR/ssign/session.json</code>; if <code>XDG_RUNTIME_DIR</code> is not
set, <code>$HOME/.cache/ssign/session.json</code>; otherwise <code>ssign/session.json</code> in the system temporary
folder.</li>
<li><strong>What</strong>: the account e-mail, the bearer token, an expiry time, the card serial and the signing
certificate. Neither the seed nor the code is written.</li>
<li><strong>How long</strong>: ssign trusts a saved token for 20 minutes, inside the token's own lifetime of about 30
minutes, and logs in again when less than 2 minutes remain.</li>
<li><strong>Permissions</strong>: on Unix systems the folder is created with mode <code>0700</code> and the file with
<code>0600</code>, readable by your user only.</li>
<li>A cache saved for another e-mail address, expired or unreadable is ignored, and ssign logs in again.</li>
</ul>
<div class="note">Whoever can read <code>session.json</code> can sign as you until the token expires. On a shared
machine, keep that in mind.</div>

<h2>What the signature contains</h2>
<p>ssign builds a standard Authenticode PKCS#7 SignedData: the file's Authenticode SHA-256 hash, the signing time, the
optional description and URL (<code>-n</code>, <code>-u</code>), the RSA signature from the cloud, your certificate and
the Certum “Code Signing 2021 CA” intermediate, and the RFC 3161 timestamp token. It is embedded in the PE certificate
table and the PE checksum is updated. The digest sent to the cloud is the SHA-256 of the signed attributes that carry
the file's hash.</p>

<h2>The SimplySign protocol</h2>
<p>ssign speaks the cloud protocol directly:</p>
{flow("en")}
<p>The protocol was reverse-engineered from the author's own licensed SimplySign Desktop 2.9.14 install, for
interoperability, with a redacting proxy that recorded the structure of the requests and masked every value: no token,
code, PIN or signature was written to disk. The whole flow is plain HTTPS, with no cryptographic activation step:
session control is the OAuth bearer token. SimplySign Desktop's own PKCS#11 module is a thin shim that relays to the
running desktop application, which is why it cannot sign on its own. The full reference, endpoints and dead ends:
<a href="{PROTOCOL}">docs/simplysign-protocol.md</a>.</p>
""")
        return ("Fonctionnement et sécurité de ssign avec le cloud Certum SimplySign : protocole, secrets, cache",
                "Ce que ssign envoie au cloud Certum SimplySign et au serveur d'horodatage, pourquoi la graine TOTP est un "
                "secret à longue durée, où le jeton de session est gardé, et comment fonctionne le protocole SimplySign.",
                f"""
<h1>Comment ssign fonctionne, et ce qu'il fait de vos secrets</h1>
<p class="lead">ssign est un client indépendant du service de signature cloud SimplySign. Voici ce qui quitte votre
machine, ce qui est gardé sur le disque, et ce qu'il faut protéger.</p>

<h2>Ce qui est envoyé, et à qui</h2>
<div class="table"><table><thead><tr><th>Destination</th><th>Ce que ssign envoie</th></tr></thead><tbody>
<tr><td><code>cloudsign.webnotarius.pl</code><br><span class="muted">HTTPS</span></td><td><ul>
<li>Connexion : votre e-mail et le code à 6 chiffres du moment, ainsi que les identifiants de client OAuth de la
connexion web SimplySign. Ces identifiants sont des constantes de l'application, identiques pour tous les
utilisateurs de SimplySign Desktop, et non votre secret.</li>
<li>Ensuite, avec le jeton d'accès (bearer token) obtenu : la demande de votre carte et de votre certificat, puis pour
chaque signature une empreinte SHA-256 calculée sur votre machine, accompagnée de votre certificat de signature.</li>
</ul></td></tr>
<tr><td>Serveur d'horodatage<br><span class="muted"><code>http://time.certum.pl/</code> par défaut, modifiable avec
<code>--timestamp-url</code></span></td><td>Une requête RFC 3161 contenant l'empreinte SHA-256 de la signature.</td></tr>
<tr><td>Personne</td><td>Vos fichiers, hachés localement, et votre graine TOTP, dont le code est calculé
localement.</td></tr>
</tbody></table></div>
<p>Les certificats HTTPS sont vérifiés via le magasin de certificats du système d'exploitation.</p>

<h2>La connexion et la clé</h2>
<ul>
<li>La connexion est un flux OAuth 2.0 « authorization code » passant par le fournisseur d'identité CAS de Certum. Les
identifiants sont l'e-mail et le code à 6 chiffres ; aucun mot de passe de compte n'intervient.</li>
<li>Elle renvoie un jeton d'accès valable environ 30 minutes. La carte SimplySign ne demande pas de PIN
(<code>pinrequired: false</code>) : le jeton d'accès est le seul contrôle.</li>
<li>La clé est une RSA-4096, et la clé privée reste dans le HSM du cloud. ssign ne reçoit que des signatures.</li>
</ul>

<h2 id="seed">La graine TOTP est un secret à longue durée</h2>
<p><code>-O/--otp</code> (variable d'environnement <code>CERTUM_OTP</code>), c'est votre graine TOTP, le secret base32
derrière votre appli d'authentification. <strong>Elle est à longue durée</strong> : quiconque l'a, <em>avec</em> votre
e-mail, peut signer du code en votre nom, indéfiniment, jusqu'à ce que vous régénériez le QR code SimplySign.
Traitez-la comme une clé privée.</p>
<ul>
<li><strong>Jamais</strong> en argument de ligne de commande : elle finit dans l'historique du shell et dans la liste
des processus. Utilisez la variable d'environnement.</li>
<li>Préférez <strong><code>-T/--token</code></strong> (un code à usage unique) pour signer à la main en local : la
graine ne quitte alors jamais votre appli d'authentification.</li>
<li>En CI, stockez-la comme <strong>secret d'environnement protégé avec relecteurs requis</strong>
(<a href="{p('github-actions')}#approval">comment faire</a>), pas comme un simple secret de dépôt.</li>
<li>En cas de fuite, <strong>changez-la</strong> : régénérez le QR code chez Certum.</li>
</ul>
<p>L'e-mail du compte n'est pas sensible. Le code à 6 chiffres expire en 30 secondes environ et présente peu de
risque.</p>
<p>En mémoire, la commande garde la graine ou le code dans un tampon effacé dès qu'il ne sert plus. Cela ne peut rien
contre une exposition antérieure au démarrage de ssign : une valeur passée avec <code>--otp</code> est visible dans
<code>/proc/&lt;pid&gt;/cmdline</code>, et une valeur passée par <code>CERTUM_OTP</code> dans
<code>/proc/&lt;pid&gt;/environ</code>.</p>

<h2 id="cache">Le cache de session</h2>
<p>Pour éviter une seconde connexion (Certum n'accepte chaque code qu'une fois), la commande <code>ssign</code> et le
module PKCS#11 enregistrent la session après la connexion, et la réutilisent aux exécutions suivantes.</p>
<ul>
<li><strong>Où</strong> : <code>$XDG_RUNTIME_DIR/ssign/session.json</code> ; si <code>XDG_RUNTIME_DIR</code> n'est pas
défini, <code>$HOME/.cache/ssign/session.json</code> ; sinon <code>ssign/session.json</code> dans le dossier temporaire
du système.</li>
<li><strong>Quoi</strong> : l'e-mail du compte, le jeton d'accès, une heure d'expiration, le numéro de carte et le
certificat de signature. Ni la graine ni le code ne sont écrits.</li>
<li><strong>Combien de temps</strong> : ssign fait confiance à un jeton enregistré pendant 20 minutes, en deçà de sa
durée de vie d'environ 30 minutes, et se reconnecte quand il reste moins de 2 minutes.</li>
<li><strong>Permissions</strong> : sur les systèmes Unix, le dossier est créé en mode <code>0700</code> et le fichier en
<code>0600</code>, lisibles par votre seul utilisateur.</li>
<li>Un cache enregistré pour une autre adresse e-mail, expiré ou illisible est ignoré, et ssign se reconnecte.</li>
</ul>
<div class="note">Quiconque peut lire <code>session.json</code> peut signer en votre nom jusqu'à l'expiration du jeton.
Gardez-le en tête sur une machine partagée.</div>

<h2>Ce que contient la signature</h2>
<p>ssign construit un SignedData PKCS#7 Authenticode standard : l'empreinte Authenticode SHA-256 du fichier, l'heure de
signature, la description et l'URL facultatives (<code>-n</code>, <code>-u</code>), la signature RSA du cloud, votre
certificat et l'intermédiaire Certum « Code Signing 2021 CA », et le jeton d'horodatage RFC 3161. Il est intégré à la
table des certificats du fichier PE, dont la somme de contrôle est mise à jour. L'empreinte envoyée au cloud est le
SHA-256 des attributs signés qui portent l'empreinte du fichier.</p>

<h2>Le protocole SimplySign</h2>
<p>ssign parle directement le protocole du cloud :</p>
{flow("fr")}
<p>Le protocole a été reconstitué par rétro-ingénierie à partir de l'installation sous licence de SimplySign Desktop
2.9.14 de l'auteur, à des fins d'interopérabilité, avec un proxy qui enregistrait la structure des requêtes en masquant
chaque valeur : aucun jeton, code, PIN ni signature n'a été écrit sur le disque. Tout le flux est du HTTPS simple, sans
étape d'activation cryptographique : le contrôle de session repose sur le jeton d'accès OAuth. Le module PKCS#11 de
SimplySign Desktop n'est qu'une fine couche qui relaie vers l'application de bureau en cours d'exécution, et c'est
pourquoi il ne peut pas signer seul. La référence complète, avec les points d'accès et les fausses pistes :
<a href="{PROTOCOL}">docs/simplysign-protocol.md</a> (en anglais).</p>
""")

    if page == "faq":
        items = faq_items(lang)
        body = "\n".join(f'<details class="faq"><summary><h2>{html.escape(q)}</h2></summary>{a}</details>'
                         for q, a in items)
        if en:
            return ("ssign FAQ: Certum SimplySign on Linux, in CI and without SimplySign Desktop",
                    "Answers about signing Windows executables with Certum SimplySign on Linux and macOS: CI, supported "
                    "file types, TOTP seed, login errors, session reuse, Docker, SimplySign Desktop login loop.",
                    f"""
<h1>Questions and answers</h1>
<p class="lead">Common questions about ssign and Certum SimplySign code signing. Something missing? Ask on
<a href="{DISCORD}">Discord</a>.</p>
{body}
""")
        return ("FAQ ssign : Certum SimplySign sous Linux, en CI et sans SimplySign Desktop",
                "Réponses sur la signature d'exécutables Windows avec Certum SimplySign sous Linux et macOS : CI, types de "
                "fichiers, graine TOTP, erreurs de connexion, réutilisation de session, Docker, boucle de SimplySign Desktop.",
                f"""
<h1>Questions et réponses</h1>
<p class="lead">Les questions fréquentes sur ssign et la signature de code avec Certum SimplySign. Il en manque une ?
Posez-la sur <a href="{DISCORD}">Discord</a>.</p>
{body}
""")
    raise KeyError(page)


# ---------------------------------------------------------------- layout

def structured_data(page, lang, title, description):
    app = {
        "@type": "SoftwareApplication",
        "@id": SITE + "#app",
        "name": "ssign",
        "description": ("Command-line tool that Authenticode-signs Windows binaries with a Certum SimplySign cloud "
                        "certificate from Linux, macOS or Windows, without SimplySign Desktop."
                        if lang == "en" else
                        "Outil en ligne de commande qui signe en Authenticode les binaires Windows avec un certificat "
                        "cloud Certum SimplySign depuis Linux, macOS ou Windows, sans SimplySign Desktop."),
        "applicationCategory": "DeveloperApplication",
        "operatingSystem": "Linux, macOS, Windows",
        "url": SITE,
        "downloadUrl": RELEASES,
        "license": "https://opensource.org/licenses/MIT",
        "codeRepository": REPO,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "EUR"},
    }
    v = version()
    if v:
        app["softwareVersion"] = v
    graph = [app, {"@type": "WebPage", "name": title, "description": description, "url": url(page, lang),
                   "inLanguage": lang, "about": {"@id": SITE + "#app"}}]
    if page == "faq":
        graph.append({"@type": "FAQPage", "url": url(page, lang), "inLanguage": lang, "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": html.unescape(re.sub(r"<[^>]+>", "", a)).strip()}}
            for q, a in faq_items(lang)]})
    return {"@context": "https://schema.org", "@graph": graph}


def french_spacing(markup):
    """Non-breaking spaces before : ; ? ! » and after «, in text only (never inside tags, code or pre),
    so French punctuation never starts a line."""
    parts = re.split(r"(<pre>.*?</pre>|<code>.*?</code>|<[^>]+>)", markup, flags=re.S)
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r" ([:;?!»])", "\u00a0\\1", parts[i]).replace("« ", "«\u00a0")
    return "".join(parts)


def render(page, lang):
    title, description, body = content(page, lang)
    if lang == "fr":
        body = french_spacing(body)
    u = UI[lang]
    up = "../" if lang == "fr" else ""
    other, other_label, other_code = u["other"]
    nav = "".join(
        f'<a href="{href(n, lang, lang)}"{" aria-current=\"page\"" if n == page else ""}>{u["nav"][n]}</a>'
        for n in PAGES)
    ld = json.dumps(structured_data(page, lang, title, description), ensure_ascii=False).replace("</", "<\\/")
    verification = ('<meta name="google-site-verification" content="' + GOOGLE_VERIFICATION + '">\n'
                    if page == "index" else "")
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
{verification}<link rel="canonical" href="{url(page, lang)}">
<link rel="alternate" hreflang="en" href="{url(page, 'en')}">
<link rel="alternate" hreflang="fr" href="{url(page, 'fr')}">
<link rel="alternate" hreflang="x-default" href="{url(page, 'en')}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="ssign">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(description)}">
<meta property="og:url" content="{url(page, lang)}">
<meta property="og:image" content="{SITE}img/og.jpg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:locale" content="{'fr_FR' if lang == 'fr' else 'en_GB'}">
<meta property="og:locale:alternate" content="{'en_GB' if lang == 'fr' else 'fr_FR'}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{html.escape(title)}">
<meta name="twitter:description" content="{html.escape(description)}">
<meta name="twitter:image" content="{SITE}img/og.jpg">
<meta name="color-scheme" content="light dark">
<link rel="icon" type="image/svg+xml" href="{up}img/favicon.svg">
<link rel="stylesheet" href="{up}style.css">
<script type="application/ld+json">{ld}</script>
</head>
<body>
<header class="site"><div class="wrap">
<a class="brand" href="{href('index', lang, lang)}"><img src="{up}img/favicon.svg" alt="" width="24" height="24"><span>s<b>sign</b></span></a>
<nav class="main">{nav}</nav>
<a class="lang" href="{href(page, other, lang)}" hreflang="{other}" lang="{other}"><img src="{up}img/{other_code.lower()}.svg" alt="" width="21" height="14">{other_label}</a>
</div></header>
<main><div class="wrap">
{body.strip()}
</div></main>
<footer class="site"><div class="wrap">
<a href="{REPO}">{u["footer_src"]}</a>
<a href="{DISCORD}">{u["footer_chat"]}</a>
<a href="{CRATE}">crates.io</a>
<span>{french_spacing(u["footer_note"]) if lang == "fr" else u["footer_note"]}</span>
</div></footer>
</body>
</html>
"""


def main():
    (DOCS / "fr").mkdir(exist_ok=True)
    for lang in ("en", "fr"):
        out = DOCS / ("fr" if lang == "fr" else "")
        for page in PAGES:
            (out / ("index.html" if page == "index" else page + ".html")).write_text(render(page, lang), encoding="utf-8")
    urls = []
    for page in PAGES:
        alts = "".join(f'<xhtml:link rel="alternate" hreflang="{l}" href="{url(page, l)}"/>' for l in ("en", "fr"))
        alts += f'<xhtml:link rel="alternate" hreflang="x-default" href="{url(page, "en")}"/>'
        for lang in ("en", "fr"):
            urls.append(f"<url><loc>{url(page, lang)}</loc>{alts}</url>")
    (DOCS / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + "\n".join(urls) + "\n</urlset>\n", encoding="utf-8")
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")


if __name__ == "__main__":
    main()
