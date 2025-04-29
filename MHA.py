#!/usr/bin/env python3
import os
import sys
import threading
import webbrowser
import argparse
import logging
import re
import socket
import quopri
import whois
from flask import Flask, request, render_template_string, url_for
from email.parser import HeaderParser
from email.utils import parseaddr
from dateutil import parser as date_parser
from typing import List, Dict, Optional
import ipaddress
import geoip2.database
from collections import Counter

# -------- base directory (works in both normal & PyInstaller onefile) --------
if getattr(sys, 'frozen', False):
    # running in PyInstaller bundle
    BASE_DIR = sys._MEIPASS
else:
    # running in normal Python
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, 'data')
MMDB_PATH = os.path.join(DATA_DIR, 'GeoLite2-Country.mmdb')

# ---------- HTML Template ----------
TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mail Header Analyzer</title>
  <!-- serve Tailwind locally -->
  <script src="{{ url_for('static', filename='tailwinds.16') }}"></script>
  <!-- serve Chart.js locally -->
  <script src="{{ url_for('static', filename='chart.js') }}"></script>
</head>
<body class="bg-gray-900 text-gray-200">
  <!-- Loading Overlay -->
  <div id="loading-overlay" class="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center hidden z-50">
    <svg class="animate-spin h-16 w-16 text-orange-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
    </svg>
    <p class="mt-4 text-xl text-orange-400">Processing...</p>
  </div>
  <nav class="bg-gray-800 shadow">
    <div class="container mx-auto p-4 flex justify-between items-center">
      <h1 class="text-3xl font-bold text-orange-500">Mail Header Analyzer</h1>
      <button id="export-btn" onclick="window.print()" class="px-4 py-2 bg-orange-500 text-gray-900 font-semibold rounded hover:bg-orange-600">Export PDF</button>
    </div>
  </nav>
  <main class="container mx-auto py-8 px-2">
    <form id="analyze-form" method="post" class="mb-8" onsubmit="document.getElementById('loading-overlay').classList.remove('hidden')">
      <textarea name="headers" class="w-full h-48 p-2 bg-gray-800 border border-gray-700 rounded text-gray-100" placeholder="Paste mail headers here" required>{{ request.form.get('headers','') }}</textarea>
      <div class="mt-4">
        <button type="submit" class="px-4 py-2 bg-orange-500 text-gray-900 rounded hover:bg-orange-600">Analyze</button>
        <button type="reset" class="ml-4 px-4 py-2 bg-gray-600 text-gray-200 rounded hover:bg-gray-700">Clear</button>
      </div>
    </form>

    {% if summary %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-bold mb-4 text-orange-500">Summary</h2>
      <dl class="grid grid-cols-1 md:grid-cols-2 gap-4 text-gray-200">
        <div><dt class="font-medium">Date:</dt><dd>{{ summary.Date }}</dd></div>
        <div><dt class="font-medium">Travel Time:</dt><dd>{{ total_delay }}</dd></div>
        <div><dt class="font-medium">From:</dt><dd>{{ summary.From }}</dd></div>
        <div><dt class="font-medium">To:</dt><dd>{{ summary.To }}</dd></div>
        <div><dt class="font-medium">Subject:</dt><dd>{{ summary.Subject }}</dd></div>
        <div><dt class="font-medium">SPF:</dt><dd>{{ summary.SPF or 'N/A' }}</dd></div>
        <div><dt class="font-medium">Domain Registered:</dt><dd>{{ summary.whois_created or 'N/A' }}</dd></div>
        <div><dt class="font-medium">DMARC:</dt><dd>{{ summary.DMARC or 'N/A' }}</dd></div>
        <div><dt class="font-medium">Domain Updated:</dt><dd>{{ summary.whois_updated or 'N/A' }}</dd></div>
        <div><dt class="font-medium">DKIM:</dt><dd>{{ summary.DKIM or 'N/A' }}</dd></div>
      </dl>
    </section>
    {% if whois_full %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <details class="bg-gray-800 rounded-lg">
        <summary class="cursor-pointer text-2xl font-bold text-orange-500 mb-2">Full WHOIS</summary>
        <pre class="whitespace-pre-wrap bg-gray-900 p-4 rounded text-gray-100">{{ whois_full }}</pre>
      </details>
    </section>
    {% endif %}
    {% endif %}

    {% if entries %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Hop Delays</h2>
      <div class="relative w-full h-64 mb-8">
        <canvas id="hopDelayChart" class="absolute inset-0"></canvas>
      </div>
    </section>
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Hop Journey</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700">
            <tr>
              <th class="px-4 py-2">Hop</th>
              <th>From</th>
              <th>By</th>
              <th>Timestamp</th>
              <th class="text-white">Delay</th>
            </tr>
          </thead>
          <tbody>
            {% for e in entries %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ e.hop }}</td>
              <td class="px-4 py-2">{{ e.frm }}</td>
              <td class="px-4 py-2">{{ e.by }}</td>
              <td class="px-4 py-2">{{ e.timestamp }}</td>
              <td class="px-4 py-2 text-white">{{ e.duration }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if ips %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted IPs</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700">
            <tr>
              <th class="px-4 py-2">IP Address</th>
              <th>Count</th>
              <th>Version</th>
              <th>Type</th>
              <th>rDNS</th>
              <th>Country</th>
            </tr>
          </thead>
          <tbody>
            {% for ip in ips %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ ip.address }}</td>
              <td class="px-4 py-2">{{ ip.count }}</td>
              <td class="px-4 py-2">v{{ ip.version }}</td>
              <td class="px-4 py-2">{{ ip.type }}</td>
              <td class="px-4 py-2">{{ ip.rdns or 'N/A' }}</td>
              <td class="px-4 py-2">{{ ip.country or 'N/A' }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if domains %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted Domains</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700">
            <tr>
              <th class="px-4 py-2">Domain</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {% for d in domains %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ d.domain }}</td>
              <td class="px-4 py-2">{{ d.count }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if links %}
    <section class="bg-gray-800 shadow-lg rounded-lg p-6">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted Links</h2>
      <div class="w-full">
        <table class="table-fixed w-full border-collapse text-gray-100">
          <thead class="bg-gray-700">
            <tr>
              <th class="w-1/4 px-2 py-1">Link Text</th>
              <th class="w-3/4 px-2 py-1">URL</th>
              <th class="w-16 px-2 py-1">Count</th>
            </tr>
          </thead>
          <tbody>
            {% for l in links %}
            <tr class="border-t border-gray-700">
              <td class="px-2 py-1 break-words">{{ l.text|safe }}</td>
              <td class="px-2 py-1 break-words">{{ l.url }}</td>
              <td class="px-2 py-1 text-center">{{ l.count }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}
  </main>

  <script>
    {% if entries %}
    const ctx = document.getElementById('hopDelayChart').getContext('2d');
    const hops = {{ entries|tojson }};
    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: hops.map(h => `Hop ${h.hop}`),
        datasets: [{ label: 'Delay (s)', data: hops.map(h => h.delay_secs), barThickness: 20 }]
      },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        scales: { x: { beginAtZero: true, suggestedMax: {{ max_delay }} }, y: { ticks: { color: '#fff' } } },
        plugins: { legend: { display: false } }
      }
    });
    {% endif %}
  </script>
</body>
</html>
'''

def _parse_date(text: str) -> Optional[float]:
    try:
        return date_parser.parse(text, fuzzy=True).timestamp()
    except:
        return None

def _format_duration(seconds: int) -> str:
    parts = []
    for name, cnt in [('hr',3600),('min',60),('sec',1)]:
        val, seconds = divmod(seconds, cnt)
        if val:
            parts.append(f"{val}{name}")
    return ' '.join(parts) or '0sec'

def parse_summary(raw: str) -> Dict[str, str]:
    headers = HeaderParser().parsestr(raw)
    summary = {'From':'','To':'','Subject':'','Date':''}
    summary.update({k: headers.get(k, '') for k in summary})
    summary.update({'SPF': None, 'DKIM': None, 'DMARC': None})
    for auth in headers.get_all('Authentication-Results', []):
        if m := re.search(r'spf=(pass|fail|neutral|softfail|temperror|permerror)', auth, re.I):
            summary['SPF'] = m.group(1).lower()
        if m := re.search(r'dkim=(pass|fail|neutral|policy|none)', auth, re.I):
            summary['DKIM'] = m.group(1).lower()
        if m := re.search(r'dmarc=(pass|fail|bestguess|none)', auth, re.I):
            summary['DMARC'] = m.group(1).lower()
    if not summary['SPF'] and headers.get('Received-SPF'):
        summary['SPF'] = headers.get('Received-SPF').split()[0]
    return summary

def parse_received(raw: str) -> List[Dict]:
    headers = HeaderParser().parsestr(raw)
    recs = headers.get_all('Received') or []
    recs.reverse()
    hops = []
    prev_ts: Optional[float] = None

    for idx, r in enumerate(recs, start=1):
        parts = r.rsplit(';', 1)
        raw_ts = parts[-1].strip() if parts[-1] else ''
        try:
            dt = date_parser.parse(raw_ts, fuzzy=True)
            iso_ts = dt.isoformat()
            ts_val = dt.timestamp()
        except Exception:
            iso_ts = raw_ts
            ts_val = None

        if prev_ts is not None and ts_val is not None:
            delay = int(ts_val - prev_ts) if ts_val > prev_ts else 0
        else:
            delay = 0

        prev_ts = ts_val if ts_val is not None else prev_ts

        m = re.search(r'from\s+(.*?)\s+by\s+(.*?)(?:\s|$)', parts[0], re.I)
        frm, by = (m.group(1), m.group(2)) if m else ('','')

        hops.append({
            'hop': idx,
            'frm': frm,
            'by': by,
            'timestamp': iso_ts,
            'duration': _format_duration(delay),
            'delay_secs': delay
        })

    return hops

def extract_ips(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')
    ipv4_re = re.compile(
        r'(?<![\d.])((?:25[0-5]|2[0-4]\d|[01]?\d?\d)'
        r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})(?![\d.])'
    )
    ipv6_re = re.compile(
        r'(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])'
    )
    found = [ip for rgx in (ipv4_re, ipv6_re) for ip in rgx.findall(decoded)]
    counts = Counter(found)

    reader = geoip2.database.Reader(MMDB_PATH)
    results = []
    for ip_str, cnt in counts.items():
        try:
            obj = ipaddress.ip_address(ip_str)
        except:
            continue
        rdns = None
        try:
            rdns = socket.gethostbyaddr(ip_str)[0]
        except:
            pass
        country = None
        if obj.is_global:
            try:
                country = reader.country(ip_str).country.name
            except:
                pass
        results.append({
            'address': ip_str,
            'count': cnt,
            'version': obj.version,
            'type': 'PUBLIC' if obj.is_global else 'PRIVATE' if obj.is_private else 'OTHER',
            'rdns': rdns,
            'country': country
        })
    reader.close()
    return results

def extract_links(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')
    links = [{'text': m.group(2), 'url': m.group(1)}
             for m in re.finditer(r'<a[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>', decoded, re.I)]
    for m in re.finditer(r'(https?://[^\s<>"\']+)', decoded):
        url = m.group(1)
        if not any(l['url'] == url for l in links):
            links.append({'text': url, 'url': url})
    counts = Counter(l['url'] for l in links)
    uniq = []
    for l in links:
        if not any(u['url'] == l['url'] for u in uniq):
            uniq.append({'text': l['text'], 'url': l['url'], 'count': counts[l['url']]})
    return uniq

def extract_domains(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')
    email_domains = re.findall(r'[\w\.-]+@([\w\.-]+)', decoded)
    url_domains = re.findall(r'https?://([\w\.-]+)', decoded)
    counts = Counter(email_domains + url_domains)
    return [{'domain': dom, 'count': cnt} for dom, cnt in counts.items()]

def create_app() -> Flask:
    app = Flask(__name__, static_folder=DATA_DIR, static_url_path='/static')
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        summary, entries, ips, domains, links = {}, [], [], [], []
        total_delay, max_delay = '', 0
        whois_full = None

        if request.method == 'POST':
            raw = request.form['headers']
            summary = parse_summary(raw)

            # WHOIS lookup
            email_addr = parseaddr(summary['From'])[1]
            full_dom = email_addr.split('@', 1)[1] if '@' in email_addr else None
            if full_dom:
                parts = full_dom.split('.')
                whois_dom = '.'.join(parts[-2:]) if len(parts) >= 2 else full_dom
                try:
                    w = whois.whois(whois_dom)
                    whois_full = getattr(w, 'text', None) or '\n'.join(f"{k}: {v}" for k, v in w.items())
                    for key, val in (('whois_created', w.creation_date), ('whois_updated', w.updated_date)):
                        if val:
                            dt = val[0] if isinstance(val, list) else val
                            if isinstance(dt, str):
                                dt = date_parser.parse(dt)
                            summary[key] = dt.isoformat()
                        else:
                            summary[key] = None
                except Exception:
                    app.logger.exception(f"WHOIS failed for {whois_dom}")
                    summary['whois_created'] = None
                    summary['whois_updated'] = None

            entries = parse_received(raw)
            ips = extract_ips(raw)
            domains = extract_domains(raw)
            links = extract_links(raw)
            if entries:
                total_delay = _format_duration(sum(e['delay_secs'] for e in entries))
                max_delay = max(e['delay_secs'] for e in entries)

        return render_template_string(
            TEMPLATE,
            summary=summary,
            entries=entries,
            ips=ips,
            domains=domains,
            links=links,
            total_delay=total_delay,
            max_delay=max_delay,
            whois_full=whois_full
        )

    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mail Header Analyzer')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-b', '--bind', default='127.0.0.1', help='Bind address')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
    args = parser.parse_args()

    app = create_app()
    if args.debug:
        app.debug = True
    threading.Timer(1, lambda: webbrowser.open_new(f"http://{args.bind}:{args.port}/")).start()
    app.run(host=args.bind, port=args.port, use_reloader=False)
